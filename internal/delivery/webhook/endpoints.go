package webhook

import (
	"errors"
	"net/url"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const (
	// MaxEndpointURLLength bounds a stored destination URL in bytes.
	MaxEndpointURLLength = 2048
)

var (
	// ErrInvalidEndpoint means a registration, status change or stored endpoint is not usable.
	ErrInvalidEndpoint = errors.New("webhook endpoint is invalid")
	// ErrEndpointUnavailable means no active endpoint exists at the requested subscription revision.
	ErrEndpointUnavailable = errors.New("webhook endpoint is unavailable")
)

// EndpointRegistration is a caller-supplied endpoint revision. The URL is sensitive: it may embed a
// receiver token, so it is never logged or stored in an attempt row.
type EndpointRegistration struct {
	ID                  string
	URL                 string
	KeyID               string
	SubscriptionVersion uint32
}

// Validate checks the bounded identity, the signing key reference and the static URL rules. Name
// resolution and address vetting still happen on every delivery dial.
func (r EndpointRegistration) Validate() error {
	if err := ValidateEndpointID(r.ID); err != nil {
		return err
	}
	if !keyIDPattern.MatchString(r.KeyID) {
		return ErrInvalidEndpoint
	}
	if r.SubscriptionVersion < 1 || r.SubscriptionVersion > MaxSubscriptionVersion {
		return ErrInvalidEndpoint
	}
	return ValidateEndpointURL(r.URL)
}

// ValidateEndpointID checks the tenant-visible endpoint identity.
func ValidateEndpointID(endpointID string) error {
	if !endpointIDPattern.MatchString(endpointID) {
		return ErrInvalidEndpoint
	}
	return nil
}

var endpointURLEgress = func() *Egress {
	egress, err := NewEgress(EgressPolicy{}, nil)
	if err != nil {
		panic("webhook endpoint URL policy is invalid")
	}
	return egress
}()

// ValidateEndpointURL applies the static egress rules plus registry-only bounds: HTTPS only, no
// userinfo, no fragment, a dotted hostname or public literal address, an allowed port, no control or
// whitespace bytes and a bounded length. A fragment is rejected because it is never sent and would
// make two registrations look equal while delivering the same bytes.
func ValidateEndpointURL(raw string) error {
	if len(raw) < 1 || len(raw) > MaxEndpointURLLength {
		return ErrInvalidEndpoint
	}
	for index := 0; index < len(raw); index++ {
		if raw[index] <= 0x20 || raw[index] == 0x7f {
			return ErrInvalidEndpoint
		}
	}
	target, err := url.Parse(raw)
	if err != nil {
		return ErrInvalidEndpoint
	}
	if target.Fragment != "" || target.RawFragment != "" {
		return ErrInvalidEndpoint
	}
	if err := endpointURLEgress.ValidateURL(target); err != nil {
		return ErrInvalidEndpoint
	}
	return nil
}

// Endpoint is one stored endpoint revision. Version increases by one on every accepted change and
// is used for optimistic concurrency, including status changes.
type Endpoint struct {
	Tenant              tenancy.TenantID
	ID                  string
	URL                 string
	KeyID               string
	SubscriptionVersion uint32
	Status              EndpointStatus
	Version             int64
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// Registration returns the registration fields of the stored endpoint.
func (e Endpoint) Registration() EndpointRegistration {
	return EndpointRegistration{
		ID:                  e.ID,
		URL:                 e.URL,
		KeyID:               e.KeyID,
		SubscriptionVersion: e.SubscriptionVersion,
	}
}
