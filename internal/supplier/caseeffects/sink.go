package caseeffects

import (
	"context"
	"errors"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/supplier/cases"
)

type CaseExpiryRepository interface {
	Expire(context.Context, tenancy.TenantID, string) (cases.Case, error)
}

// BoundSink joins the provider-neutral notification adapter with the case
// repository's locked, idempotent expiry transition.
type BoundSink struct {
	Reminders ReminderSink
	Cases     CaseExpiryRepository
}

func (s BoundSink) DeliverReminder(ctx context.Context, key, digest, occurrence string, recipients []string, deadline time.Time) error {
	if s.Reminders == nil {
		return errors.New("supplier case reminder sink is unavailable")
	}
	return s.Reminders.DeliverReminder(ctx, key, digest, occurrence, recipients, deadline)
}
func (s BoundSink) ExpireSupplierCase(ctx context.Context, tenantID, caseID string) error {
	if s.Cases == nil {
		return errors.New("supplier case expiry repository is unavailable")
	}
	_, err := s.Cases.Expire(ctx, tenancy.TenantID(tenantID), caseID)
	return err
}
