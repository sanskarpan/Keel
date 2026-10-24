package webhook

import (
	"errors"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

// MaxEndpointLimit bounds a tenant's configured active-endpoint limit.
const MaxEndpointLimit = 10000

var (
	// ErrEndpointPolicyConflict means a policy change reused an ID or expected version.
	ErrEndpointPolicyConflict = errors.New("webhook endpoint policy conflicts with an existing change")
)

// EndpointLimitChange creates or updates one tenant's active-endpoint limit. ExpectedVersion zero
// creates the tenant policy; a positive value updates only on an exact version match.
type EndpointLimitChange struct {
	Tenant          tenancy.TenantID
	ChangeID        string
	RequestedBy     string
	Limit           int
	Reason          string
	ExpectedVersion int64
}

// Validate checks the tenant, change identity, actor, limit, reason and expected version.
func (c EndpointLimitChange) Validate() error {
	if string(c.Tenant) == "" || string(c.Tenant) == zeroTenant {
		return ErrInvalidEndpoint
	}
	if _, err := tenancy.ParseTenantID(string(c.Tenant)); err != nil {
		return ErrInvalidEndpoint
	}
	if !reconciliationIDPattern.MatchString(c.ChangeID) {
		return ErrInvalidEndpoint
	}
	if !reconciliationActorPattern.MatchString(c.RequestedBy) {
		return ErrInvalidEndpoint
	}
	if c.Limit < 1 || c.Limit > MaxEndpointLimit {
		return ErrInvalidEndpoint
	}
	if err := validateReplayReason(c.Reason); err != nil {
		return ErrInvalidEndpoint
	}
	if c.ExpectedVersion < 0 || c.ExpectedVersion > 9007199254740991 {
		return ErrInvalidEndpoint
	}
	return nil
}

// EndpointLimitPolicy is the durable tenant policy after a change.
type EndpointLimitPolicy struct {
	ChangeID            string
	Version             int64
	ActiveEndpointLimit int
	UpdatedAt           time.Time
}
