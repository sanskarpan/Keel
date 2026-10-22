package webhook

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const (
	// DeliveryIdentityVersion names the logical delivery key format.
	DeliveryIdentityVersion = "webhook-delivery-v1"
	// MaxSubscriptionVersion bounds the subscription revision space.
	MaxSubscriptionVersion = 1_000_000
)

var (
	// ErrInvalidDelivery means a delivery identity or wire header violates the bounded contract.
	ErrInvalidDelivery = errors.New("webhook delivery identity is invalid")

	eventIDPattern    = regexp.MustCompile(`^[A-Za-z0-9_.:-]{8,128}$`)
	endpointIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	deliveryIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	attemptIDPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	zeroTenant        = "00000000-0000-0000-0000-000000000000"
)

// Identity is the logical delivery identity: one tenant event delivered to one endpoint under one
// subscription revision. Retries and replay attempts reuse it unchanged, so a delivery store can
// enforce uniqueness on it. The delivery ID and attempt ID are deliberately not part of it.
type Identity struct {
	Tenant              tenancy.TenantID
	EventID             string
	EndpointID          string
	SubscriptionVersion uint32
}

// Validate checks every bounded field.
func (i Identity) Validate() error {
	if string(i.Tenant) == "" || string(i.Tenant) == zeroTenant {
		return ErrInvalidDelivery
	}
	if _, err := tenancy.ParseTenantID(string(i.Tenant)); err != nil {
		return ErrInvalidDelivery
	}
	if !eventIDPattern.MatchString(i.EventID) {
		return ErrInvalidDelivery
	}
	if !endpointIDPattern.MatchString(i.EndpointID) {
		return ErrInvalidDelivery
	}
	if i.SubscriptionVersion < 1 || i.SubscriptionVersion > MaxSubscriptionVersion {
		return ErrInvalidDelivery
	}
	return nil
}

// Key is the canonical, collision-safe logical delivery key. Each field is length-prefixed so two
// identities cannot produce the same key by shifting bytes across a separator.
func (i Identity) Key() string {
	fields := []string{
		DeliveryIdentityVersion,
		envelopeField(string(i.Tenant)),
		envelopeField(i.EventID),
		envelopeField(i.EndpointID),
		strconv.FormatUint(uint64(i.SubscriptionVersion), 10),
	}
	return strings.Join(fields, "|")
}

// Delivery is one logical delivery plus the stable delivery ID the receiver deduplicates on.
type Delivery struct {
	ID       string
	Identity Identity
}

// Validate checks the delivery ID and the logical identity.
func (d Delivery) Validate() error {
	if !deliveryIDPattern.MatchString(d.ID) {
		return ErrInvalidDelivery
	}
	return d.Identity.Validate()
}

// Headers are the wire headers of one attempt.
type Headers struct {
	EventID    string
	DeliveryID string
	AttemptID  string
	Signature  Signature
}

const (
	// HeaderEventID carries the stable event identity.
	HeaderEventID = "Keel-Event-Id"
	// HeaderDeliveryID carries the stable logical delivery identity.
	HeaderDeliveryID = "Keel-Delivery-Id"
	// HeaderAttemptID carries the fresh per-attempt identity.
	HeaderAttemptID = "Keel-Attempt-Id"
	// HeaderSignature carries t=<unix>,kid=<id>,v1=<hex>.
	HeaderSignature = "Keel-Signature"
)

// Values renders the headers for a request.
func (h Headers) Values() map[string]string {
	return map[string]string{
		HeaderEventID:    h.EventID,
		HeaderDeliveryID: h.DeliveryID,
		HeaderAttemptID:  h.AttemptID,
		HeaderSignature:  h.Signature.String(),
	}
}

// ValidateAttemptID checks the fresh per-attempt wire identity.
func ValidateAttemptID(attemptID string) error {
	if !attemptIDPattern.MatchString(attemptID) {
		return ErrInvalidDelivery
	}
	return nil
}

// Prepare validates one attempt and signs its exact body bytes. A retry or replay calls Prepare
// again with a fresh attempt ID and timestamp: the event, delivery and logical identity stay fixed
// while the attempt ID and signature change.
func (k *Keyring) Prepare(delivery Delivery, attemptID string, body []byte, now time.Time) (Headers, error) {
	if err := delivery.Validate(); err != nil {
		return Headers{}, err
	}
	if err := ValidateAttemptID(attemptID); err != nil {
		return Headers{}, err
	}
	signature, err := k.Sign(now, body)
	if err != nil {
		return Headers{}, err
	}
	return Headers{
		EventID:    delivery.Identity.EventID,
		DeliveryID: delivery.ID,
		AttemptID:  attemptID,
		Signature:  signature,
	}, nil
}

// VerifyHeaders checks that a receiver saw a complete attempt header set whose signature covers the
// exact body. It is the reference implementation for a receiver test double, not a delivery path.
func (k *Keyring) VerifyHeaders(headers Headers, body []byte, now time.Time) error {
	if headers.EventID == "" || headers.DeliveryID == "" || headers.AttemptID == "" {
		return ErrInvalidDelivery
	}
	return k.Verify(headers.Signature, body, now)
}

func envelopeField(value string) string {
	return strconv.Itoa(len(value)) + ":" + value
}
