// Package caseeffects executes provider-neutral reminder effects with a stable
// idempotency key. Temporal/activity retries never create a new logical effect.
package caseeffects

import (
	"context"
	"errors"
	"time"

	"github.com/sanskarpan/keel/internal/supplier/caseeffects/postgres"
)

type Store interface {
	LoadContext(context.Context, postgres.Lease) (postgres.Context, bool, error)
	Complete(context.Context, postgres.Lease) error
	CompleteNoop(context.Context, postgres.Lease) error
	Fail(context.Context, postgres.Lease, time.Duration, string) error
}

// ReminderSink must deduplicate repeated calls by effectKey and reject reuse with
// a different payloadDigest. Implementations must not log recipient refs or bodies.
type ReminderSink interface {
	DeliverReminder(context.Context, string, string, string, []string, time.Time) error
}
type ExpirySink interface {
	ExpireSupplierCase(context.Context, string, string) error
}
type Sink interface {
	ReminderSink
	ExpirySink
}

type Dispatcher struct {
	store      Store
	sink       Sink
	retryDelay time.Duration
}

func New(store Store, sink Sink, retryDelay time.Duration) (*Dispatcher, error) {
	if store == nil || sink == nil || retryDelay < time.Second || retryDelay > time.Hour {
		return nil, errors.New("case reminder dispatcher dependencies are invalid")
	}
	return &Dispatcher{store: store, sink: sink, retryDelay: retryDelay}, nil
}

func (d *Dispatcher) Execute(ctx context.Context, lease postgres.Lease) error {
	current, active, err := d.store.LoadContext(ctx, lease)
	if err != nil {
		return d.retry(ctx, lease, "sink_unavailable")
	}
	if !active || current.EffectType != lease.EffectType {
		return d.store.CompleteNoop(ctx, lease)
	}
	if lease.EffectType == "case_expiry" {
		if err := d.sink.ExpireSupplierCase(ctx, string(lease.TenantID), lease.CaseID); err != nil {
			return d.retry(ctx, lease, "sink_unavailable")
		}
		return d.store.CompleteNoop(ctx, lease)
	}
	if current.CaseState != "collecting" && current.CaseState != "submitted" || len(current.Recipients) == 0 {
		return d.store.CompleteNoop(ctx, lease)
	}
	if err := d.sink.DeliverReminder(ctx, lease.EffectKey, lease.Digest, lease.Occurrence, current.Recipients, current.DeadlineAt); err != nil {
		return d.retry(ctx, lease, "sink_unavailable")
	}
	return d.store.Complete(ctx, lease)
}

func (d *Dispatcher) retry(ctx context.Context, lease postgres.Lease, code string) error {
	if err := d.store.Fail(ctx, lease, d.retryDelay, code); err != nil {
		return err
	}
	return errors.New("supplier case reminder was deferred")
}
