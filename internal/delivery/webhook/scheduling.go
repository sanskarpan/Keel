package webhook

import (
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

// DueTenant is one tenant with work available to the delivery worker. DueAt is the earliest due
// or expired-lease time, DueCount is the number of due or expired deliveries, and BatchLimit is
// the tenant's configured per-pass lease ceiling. A zero BatchLimit means the scheduler default
// applies. It carries no endpoint, payload, event or URL data.
type DueTenant struct {
	Tenant     tenancy.TenantID
	DueAt      time.Time
	DueCount   int64
	BatchLimit int
}
