package webhook

import (
	"errors"
	"regexp"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const (
	// MaxReconciliationPage bounds one dry-run reconciliation page.
	MaxReconciliationPage = 500
	// DefaultReconciliationPage is the suggested page size.
	DefaultReconciliationPage = 100
	// MaxReconciliationRunHistory bounds one reconciliation run-history listing.
	MaxReconciliationRunHistory = 100
)

var (
	// ErrInvalidReconciliation means a reconciliation request violates the bounded contract.
	ErrInvalidReconciliation = errors.New("webhook reconciliation request is invalid")
	// ErrReconciliationConflict means a run or repair ID already recorded a different result.
	ErrReconciliationConflict = errors.New("webhook reconciliation run conflicts with an existing run")
	// ErrReconciliationRepairLimit means one repair would create more deliveries than allowed.
	ErrReconciliationRepairLimit = errors.New("webhook reconciliation repair exceeds the delivery bound")

	reconciliationIDPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	reconciliationActorPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$`)
)

// ReconciliationRequest starts one bounded dry-run page. From is required only when the tenant has
// no cursor; later runs resume from the recorded cursor. The request carries no endpoint URL,
// payload or receiver content.
type ReconciliationRequest struct {
	Tenant      tenancy.TenantID
	RunID       string
	RequestedBy string
	From        *time.Time
	PageSize    int
}

// Validate checks the tenant, run identity, audit actor, optional start time and page bound.
func (r ReconciliationRequest) Validate() error {
	if string(r.Tenant) == "" || string(r.Tenant) == zeroTenant {
		return ErrInvalidReconciliation
	}
	if _, err := tenancy.ParseTenantID(string(r.Tenant)); err != nil {
		return ErrInvalidReconciliation
	}
	if !reconciliationIDPattern.MatchString(r.RunID) {
		return ErrInvalidReconciliation
	}
	if !reconciliationActorPattern.MatchString(r.RequestedBy) {
		return ErrInvalidReconciliation
	}
	if r.From != nil && r.From.IsZero() {
		return ErrInvalidReconciliation
	}
	if r.PageSize < 1 || r.PageSize > MaxReconciliationPage {
		return ErrInvalidReconciliation
	}
	return nil
}

// ReconciliationEvent is one scanned outbox event and the number of current active endpoints that
// have no delivery for it at their current subscription revision.
type ReconciliationEvent struct {
	EventID   string
	CreatedAt time.Time
	Missing   int
}

// ReconciliationPage is one durable dry-run page. Events contains every scanned event, including
// events with Missing zero, so the caller can account for cursor progress.
type ReconciliationPage struct {
	Events    []ReconciliationEvent
	Scanned   int
	GapEvents int
	Missing   int
}

// ReconciliationRunSummary is one recorded dry-run page with its audited repair totals. It
// carries counts, identities and timestamps only; no event, endpoint, URL, payload or receiver
// content. A zero CursorToEventID means the page scanned no events.
type ReconciliationRunSummary struct {
	RunID              string
	RequestedBy        string
	FromCreatedAt      time.Time
	CursorToCreatedAt  time.Time
	CursorToEventID    string
	EventsScanned      int
	GapEvents          int
	MissingDeliveries  int64
	RepairedDeliveries int
	SkippedIdentities  int
	CreatedAt          time.Time
}

// RepairRequest applies one recorded reconciliation run to its gaps using the endpoint status
// recorded at each event's time. EventLimit bounds the number of gap events revalidated in this
// repair; delivery candidates are separately capped by the database.
type RepairRequest struct {
	Tenant      tenancy.TenantID
	RepairID    string
	RunID       string
	RequestedBy string
	EventLimit  int
}

// Validate checks the tenant, both identities, audit actor and event limit.
func (r RepairRequest) Validate() error {
	if string(r.Tenant) == "" || string(r.Tenant) == zeroTenant {
		return ErrInvalidReconciliation
	}
	if _, err := tenancy.ParseTenantID(string(r.Tenant)); err != nil {
		return ErrInvalidReconciliation
	}
	if !reconciliationIDPattern.MatchString(r.RepairID) {
		return ErrInvalidReconciliation
	}
	if !reconciliationIDPattern.MatchString(r.RunID) {
		return ErrInvalidReconciliation
	}
	if !reconciliationActorPattern.MatchString(r.RequestedBy) {
		return ErrInvalidReconciliation
	}
	if r.EventLimit < 1 || r.EventLimit > MaxReconciliationPage {
		return ErrInvalidReconciliation
	}
	return nil
}

// RepairResult is the audited outcome of one repair invocation. SkippedIdentities counts the
// endpoint-event pairs with no status history or an inactive status at the event's time; those
// deliveries are never created.
type RepairResult struct {
	RepairID           string
	GapEvents          int
	InsertedDeliveries int
	SkippedIdentities  int
}

// CursorResetRequest moves a tenant reconciliation cursor backward to a bounded past time. The
// planner then rescans events from that time on its next run.
type CursorResetRequest struct {
	Tenant      tenancy.TenantID
	ResetID     string
	RequestedBy string
	To          time.Time
	Reason      string
}

// Validate checks the tenant, reset identity, audit actor, target time and reason.
func (r CursorResetRequest) Validate() error {
	if string(r.Tenant) == "" || string(r.Tenant) == zeroTenant {
		return ErrInvalidReconciliation
	}
	if _, err := tenancy.ParseTenantID(string(r.Tenant)); err != nil {
		return ErrInvalidReconciliation
	}
	if !reconciliationIDPattern.MatchString(r.ResetID) {
		return ErrInvalidReconciliation
	}
	if !reconciliationActorPattern.MatchString(r.RequestedBy) {
		return ErrInvalidReconciliation
	}
	if r.To.IsZero() {
		return ErrInvalidReconciliation
	}
	if err := validateReplayReason(r.Reason); err != nil {
		return ErrInvalidReconciliation
	}
	return nil
}

// CursorResetResult is the audited before/after watermark of one cursor reset.
type CursorResetResult struct {
	ResetID      string
	PriorAt      time.Time
	PriorEventID string
	NewAt        time.Time
}
