package webhook

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	// MaxAttemptBodyBytes bounds the exact payload one attempt may send.
	MaxAttemptBodyBytes = 1 << 20
	// MaxAttemptResponseBytes bounds how much of a receiver response is drained.
	MaxAttemptResponseBytes = 64 << 10
	// MaxAttemptNumber bounds the attempt counter accepted by the executor.
	MaxAttemptNumber = 1000

	attemptContentType = "application/json"
	attemptUserAgent   = "keel-webhook/1"
)

// AttemptRequest is one prepared delivery attempt. The caller supplies the endpoint revision it
// resolved from the registry and the exact body bytes it intends to sign; the executor does not
// fetch events, resolve endpoints or choose a destination.
type AttemptRequest struct {
	Delivery      Delivery
	Endpoint      Endpoint
	AttemptID     string
	AttemptNumber int
	Body          []byte
	Now           time.Time
}

// Validate checks that the attempt matches its delivery and that the endpoint is usable. A
// mismatch is a data-integrity error, so the caller must not send or record an attempt.
func (r AttemptRequest) Validate() error {
	if err := r.Delivery.Validate(); err != nil {
		return err
	}
	if err := ValidateAttemptID(r.AttemptID); err != nil {
		return err
	}
	if r.AttemptNumber < 1 || r.AttemptNumber > MaxAttemptNumber {
		return ErrInvalidAttempt
	}
	if len(r.Body) < 1 || len(r.Body) > MaxAttemptBodyBytes {
		return ErrInvalidDelivery
	}
	if r.Now.IsZero() {
		return ErrInvalidAttempt
	}
	if err := r.Endpoint.Registration().Validate(); err != nil {
		return err
	}
	if r.Endpoint.Status != EndpointActive {
		return ErrInvalidEndpoint
	}
	if r.Endpoint.Tenant != r.Delivery.Identity.Tenant ||
		r.Endpoint.ID != r.Delivery.Identity.EndpointID ||
		r.Endpoint.SubscriptionVersion != r.Delivery.Identity.SubscriptionVersion {
		return ErrInvalidEndpoint
	}
	return nil
}

// AttemptResult is the classified result of one attempt. A zero HTTP status means the request did
// not produce a response. Latency covers the whole exchange, including draining the bounded body.
type AttemptResult struct {
	Outcome    Outcome
	HTTPStatus int
	Latency    time.Duration
}

// Execute signs and sends exactly one attempt through the egress client. It never follows a
// redirect, never returns a receiver body and never wraps a transport error that could contain the
// destination URL; send-time failures are classified instead.
func (e *Executor) Execute(ctx context.Context, request AttemptRequest) (AttemptResult, error) {
	if e == nil || e.egress == nil || e.keyring == nil {
		return AttemptResult{}, errors.New("webhook executor is not configured")
	}
	if ctx == nil {
		return AttemptResult{}, errors.New("webhook attempt context is required")
	}
	if err := request.Validate(); err != nil {
		return AttemptResult{}, err
	}

	target, err := url.Parse(request.Endpoint.URL)
	if err != nil {
		return AttemptResult{}, ErrInvalidEndpoint
	}
	if err := e.egress.ValidateURL(target); err != nil {
		return AttemptResult{}, err
	}
	headers, err := e.keyring.Prepare(request.Delivery, request.AttemptID, request.Body, request.Now)
	if err != nil {
		return AttemptResult{}, err
	}
	if headers.Signature.KeyID != request.Endpoint.KeyID {
		return AttemptResult{}, ErrInvalidKeyring
	}

	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(request.Body))
	if err != nil {
		return AttemptResult{}, ErrInvalidEndpoint
	}
	for name, value := range headers.Values() {
		httpRequest.Header.Set(name, value)
	}
	httpRequest.Header.Set("Content-Type", attemptContentType)
	httpRequest.Header.Set("User-Agent", attemptUserAgent)

	started := time.Now()
	response, err := e.egress.Client().Do(httpRequest)
	if err != nil {
		return AttemptResult{
			Outcome: ClassifyError(err),
			Latency: time.Since(started),
		}, nil
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, MaxAttemptResponseBytes))

	outcome, err := ClassifyStatus(response.StatusCode)
	if err != nil {
		outcome = OutcomePermanent
	}
	return AttemptResult{
		Outcome:    outcome,
		HTTPStatus: response.StatusCode,
		Latency:    time.Since(started),
	}, nil
}

// Executor performs one signed HTTP attempt. It is immutable and safe for concurrent use.
type Executor struct {
	egress  *Egress
	keyring *Keyring
}

// NewExecutor requires an egress client and a signing keyring. Both are immutable and may be
// shared by a worker.
func NewExecutor(egress *Egress, keyring *Keyring) (*Executor, error) {
	if egress == nil || egress.Client() == nil {
		return nil, errors.New("webhook executor egress is required")
	}
	if keyring == nil {
		return nil, errors.New("webhook executor keyring is required")
	}
	return &Executor{egress: egress, keyring: keyring}, nil
}
