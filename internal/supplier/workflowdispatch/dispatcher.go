// Package workflowdispatch delivers immutable case intents to Temporal at least once.
package workflowdispatch

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/supplier/caseworkflow"
	"github.com/sanskarpan/keel/internal/supplier/workflowdispatch/postgres"
	"go.temporal.io/api/serviceerror"
)

const (
	LeaseDuration = time.Minute
	SendTimeout   = 15 * time.Second
)

type Store interface {
	Claim(context.Context, tenancy.TenantID, string, time.Duration) (postgres.Lease, bool, error)
	Complete(context.Context, postgres.Lease) error
	Fail(context.Context, postgres.Lease, time.Duration, string) error
}

type Sender interface {
	Deliver(context.Context, tenancy.TenantID, caseworkflow.EventSignal) error
}

type Dispatcher struct {
	store    Store
	sender   Sender
	workerID string
}

var ErrInvalidConfig = errors.New("workflow dispatcher configuration is invalid")

func New(store Store, sender Sender, workerID string) (*Dispatcher, error) {
	if store == nil || sender == nil || !validUUID(workerID) {
		return nil, ErrInvalidConfig
	}
	return &Dispatcher{store: store, sender: sender, workerID: workerID}, nil
}

// DispatchOne returns found=false when no eligible event exists. Failures are
// persisted with a bounded code; the raw Temporal error is deliberately discarded.
func (d *Dispatcher) DispatchOne(ctx context.Context, tenant tenancy.TenantID) (found bool, err error) {
	if d == nil || ctx == nil {
		return false, ErrInvalidConfig
	}
	lease, found, err := d.store.Claim(ctx, tenant, d.workerID, LeaseDuration)
	if err != nil || !found {
		return found, err
	}
	signal := caseworkflow.EventSignal{CaseID: lease.CaseID, IntentID: lease.IntentID, Version: lease.Version, EventType: lease.EventType, EventHash: lease.EventHash}
	sendCtx, cancel := context.WithTimeout(ctx, SendTimeout)
	err = d.sender.Deliver(sendCtx, lease.TenantID, signal)
	cancel()
	if err == nil {
		return true, d.store.Complete(ctx, lease)
	}
	code := classify(err)
	permanent := code == "invalid_intent" || code == "workflow_conflict"
	if failErr := d.store.Fail(ctx, lease, RetryDelay(lease.IntentID, lease.Attempt), code); failErr != nil {
		return true, errors.Join(errors.New("persist Temporal delivery failure"), failErr)
	}
	if permanent {
		return true, fmt.Errorf("supplier workflow intent quarantined: %s", code)
	}
	return true, fmt.Errorf("supplier workflow delivery deferred: %s", code)
}

func classify(err error) string {
	if errors.Is(err, caseworkflow.ErrInvalidSignal) || errors.Is(err, caseworkflow.ErrCaseMismatch) {
		return "invalid_intent"
	}
	var alreadyStarted *serviceerror.WorkflowExecutionAlreadyStarted
	if errors.As(err, &alreadyStarted) {
		return "workflow_conflict"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "temporal_timeout"
	}
	return "temporal_unavailable"
}

// RetryDelay is stable for an intent/attempt pair and bounded to 15 minutes.
// Deterministic hash jitter spreads a large retry wave without storing randomness.
func RetryDelay(intentID string, attempt uint32) time.Duration {
	if attempt == 0 {
		attempt = 1
	}
	shift := attempt - 1
	if shift > 20 {
		shift = 20
	}
	base := time.Second * time.Duration(uint64(1)<<shift)
	if base > 15*time.Minute {
		base = 15 * time.Minute
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", intentID, attempt)))
	value := binary.BigEndian.Uint16(digest[:2])
	spread := int64(base / 2)
	offset := int64(value) * spread / 65535
	return base/2 + time.Duration(offset)
}

func validUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range value {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}
