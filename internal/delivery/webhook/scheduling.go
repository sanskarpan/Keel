package webhook

import (
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

// DueTenant is one tenant with work available to the delivery worker. DueAt is the earliest due
// or expired-lease time, and DueCount is the number of due or expired deliveries. It carries no
// endpoint, payload, event or URL data.
type DueTenant struct {
	Tenant   tenancy.TenantID
	DueAt    time.Time
	DueCount int64
}
