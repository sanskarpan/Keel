package webhook

import (
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

// EndpointStatusAtQuery asks for one endpoint's status and subscription revision as of a point
// in time. It carries no URL, key, payload or receiver data.
type EndpointStatusAtQuery struct {
	Tenant tenancy.TenantID
	ID     string
	At     time.Time
}

// Validate checks the tenant, endpoint identity and query time.
func (q EndpointStatusAtQuery) Validate() error {
	if string(q.Tenant) == "" || string(q.Tenant) == zeroTenant {
		return ErrInvalidEndpoint
	}
	if _, err := tenancy.ParseTenantID(string(q.Tenant)); err != nil {
		return ErrInvalidEndpoint
	}
	if err := ValidateEndpointID(q.ID); err != nil {
		return err
	}
	if q.At.IsZero() {
		return ErrInvalidEndpoint
	}
	return nil
}

// EndpointStatusPoint is one endpoint's recorded status and subscription revision at a point in
// time, with the history version and record time that produced it.
type EndpointStatusPoint struct {
	Tenant              tenancy.TenantID
	ID                  string
	Status              EndpointStatus
	SubscriptionVersion uint32
	Version             int64
	RecordedAt          time.Time
}
