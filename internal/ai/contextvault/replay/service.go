// Package replay implements an explicitly authorized, read-only diagnostic
// access path for one immutable context-vault record version.
package replay

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/sanskarpan/keel/internal/ai/contextvault"
)

var (
	ErrInvalidRequest = errors.New("invalid context replay request")
	ErrNotAuthorized  = errors.New("context replay is not authorized")
	ErrUnavailable    = errors.New("context replay unavailable")

	uuidPattern    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	requestPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,96}$`)
)

const maxReplayDuration = 5 * time.Second
const maxRecordVersion = uint64(1<<63 - 1)

// Request contains only trusted identity and exact immutable record scope. The
// HTTP layer must derive TenantID and ActorID from authenticated server context.
type Request struct {
	TenantID  string
	ActorID   string
	RecordID  string
	Version   uint64
	Purpose   string
	Reason    string
	RequestID string
}

// Authorizer is the separately granted diagnostic policy boundary. It must
// bind its decision to every request field and fail closed on uncertainty.
type Authorizer interface {
	AuthorizeReplay(context.Context, Request) error
}

// Repository begins the one-use audit and returns only an eligible exact
// encrypted record. DeliverReplay must recheck expiry/holds while locking the
// record, hold that lock across delivery, and persist the terminal outcome.
type Repository interface {
	RecordDenied(context.Context, Request) error
	BeginReplay(context.Context, Request) (contextvault.Scope, contextvault.Envelope, error)
	FinishReplay(context.Context, Request, Outcome) error
	DeliverReplay(context.Context, Request, func() Outcome) error
}

// Outcome contains only a fixed content-free terminal classification.
type Outcome string

const (
	OutcomeComplete       Outcome = "complete"
	OutcomeIntegrityError Outcome = "integrity_failed"
	OutcomeKeyUnavailable Outcome = "key_unavailable"
	OutcomeDeliveryError  Outcome = "delivery_failed"
	OutcomeCancelled      Outcome = "cancelled"
)

// DiagnosticConsumer receives plaintext only for the duration of Consume.
// Implementations must be a trusted diagnostic sink, must not retain or log
// bytes, and must not invoke models, tools, or business mutations.
type DiagnosticConsumer interface {
	Consume(context.Context, Request, []byte) error
}

// Service composes authorization, one-use record access, and authenticated
// decryption. It intentionally has no model, tool, or business-operation port.
type Service struct {
	authorizer Authorizer
	repository Repository
	keys       contextvault.KeyWrapper
	consumer   DiagnosticConsumer
}

func NewService(authorizer Authorizer, repository Repository, keys contextvault.KeyWrapper, consumer DiagnosticConsumer) (*Service, error) {
	if authorizer == nil || repository == nil || keys == nil || consumer == nil {
		return nil, ErrInvalidRequest
	}
	return &Service{authorizer: authorizer, repository: repository, keys: keys, consumer: consumer}, nil
}

// Execute authorizes before any repository or key-provider access. The caller
// must supply a deadline; the service caps it to five seconds. Adapters must
// honor cancellation so the database lock and plaintext lifetime stay bounded.
func (s *Service) Execute(ctx context.Context, request Request) error {
	if s == nil || s.authorizer == nil || s.repository == nil || s.keys == nil || s.consumer == nil || ctx == nil ||
		!validRequest(request) {
		return ErrInvalidRequest
	}
	request.TenantID = strings.ToLower(request.TenantID)
	request.ActorID = strings.ToLower(request.ActorID)
	request.RecordID = strings.ToLower(request.RecordID)
	if _, ok := ctx.Deadline(); !ok {
		return ErrInvalidRequest
	}
	deadlineCtx, cancel := context.WithTimeout(ctx, maxReplayDuration)
	defer cancel()
	if err := s.authorizer.AuthorizeReplay(deadlineCtx, request); err != nil {
		deniedCtx, deniedCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer deniedCancel()
		_ = s.repository.RecordDenied(deniedCtx, request)
		return ErrNotAuthorized
	}
	if err := deadlineCtx.Err(); err != nil {
		return err
	}
	scope, envelope, err := s.repository.BeginReplay(deadlineCtx, request)
	if err != nil {
		return ErrUnavailable
	}
	defer wipe(envelope.WrappedDEK)
	defer wipe(envelope.Nonce)
	defer wipe(envelope.Ciphertext)
	finish := func(outcome Outcome) error {
		finishCtx, finishCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer finishCancel()
		return s.repository.FinishReplay(finishCtx, request, outcome)
	}
	if deadlineCtx.Err() != nil || scope.TenantID != request.TenantID || scope.RecordID != request.RecordID || scope.Version != request.Version {
		_ = finish(OutcomeCancelled)
		return ErrUnavailable
	}
	plaintext, err := contextvault.Decrypt(deadlineCtx, s.keys, scope, envelope)
	if err != nil {
		outcome := OutcomeIntegrityError
		if deadlineCtx.Err() != nil {
			outcome = OutcomeCancelled
		} else if errors.Is(err, contextvault.ErrKeyUnavailable) {
			outcome = OutcomeKeyUnavailable
		}
		_ = finish(outcome)
		return ErrUnavailable
	}
	defer wipe(plaintext)
	if len(plaintext) > contextvault.MaxPlaintextBytes {
		_ = finish(OutcomeIntegrityError)
		return ErrUnavailable
	}
	if err := s.repository.DeliverReplay(deadlineCtx, request, func() Outcome {
		if deadlineCtx.Err() != nil {
			return OutcomeCancelled
		}
		if err := s.consumer.Consume(deadlineCtx, request, plaintext); err != nil {
			if deadlineCtx.Err() != nil {
				return OutcomeCancelled
			}
			return OutcomeDeliveryError
		}
		return OutcomeComplete
	}); err != nil {
		return ErrUnavailable
	}
	return nil
}

func validRequest(request Request) bool {
	return uuidPattern.MatchString(request.TenantID) && !strings.EqualFold(request.TenantID, "00000000-0000-0000-0000-000000000000") &&
		uuidPattern.MatchString(request.ActorID) && !strings.EqualFold(request.ActorID, "00000000-0000-0000-0000-000000000000") &&
		uuidPattern.MatchString(request.RecordID) && !strings.EqualFold(request.RecordID, "00000000-0000-0000-0000-000000000000") &&
		request.Version > 0 && request.Version <= maxRecordVersion && requestPattern.MatchString(request.RequestID) &&
		(request.Purpose == "read_only_replay" || request.Purpose == "incident_review") &&
		(request.Reason == "support_diagnostic" || request.Reason == "security_investigation" || request.Reason == "customer_requested")
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
