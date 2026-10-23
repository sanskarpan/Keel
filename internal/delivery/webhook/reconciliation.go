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

// RepairRequest applies one recorded reconciliation run to its current gaps. EventLimit bounds the
// number of gap events revalidated in this repair; delivery candidates are separately capped by
// the database.
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

// RepairResult is the audited outcome of one repair invocation.
type RepairResult struct {
	RepairID           string
	GapEvents          int
	InsertedDeliveries int
}
