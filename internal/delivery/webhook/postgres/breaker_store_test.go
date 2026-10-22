package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func TestStoreBreakerRejectsInvalidInput(t *testing.T) {
	store := newStore(t, unreachableRegistry(t).db)
	ctx := context.Background()
	tenant := randomTenant(t)
	endpointID := uuid.NewString()
	valid := webhook.BreakerState{Status: webhook.BreakerClosed, Failures: 1}
	cases := map[string]struct {
		ctx        context.Context
		tenant     tenancy.TenantID
		endpointID string
		expected   int64
		state      webhook.BreakerState
		wantErr    error
	}{
		"nil load context":       {ctx: nil, tenant: tenant, endpointID: endpointID, wantErr: nil},
		"empty load tenant":      {ctx: ctx, tenant: "", endpointID: endpointID, wantErr: webhook.ErrInvalidEndpoint},
		"invalid load id":        {ctx: ctx, tenant: tenant, endpointID: "short", wantErr: webhook.ErrInvalidEndpoint},
		"nil save context":       {ctx: nil, tenant: tenant, endpointID: endpointID, expected: 0, state: valid},
		"save expected negative": {ctx: ctx, tenant: tenant, endpointID: endpointID, expected: -1, state: valid, wantErr: webhook.ErrInvalidBreakerState},
		"save expected above cap": {
			ctx: ctx, tenant: tenant, endpointID: endpointID, expected: maxEndpointVersion + 1, state: valid,
			wantErr: webhook.ErrInvalidBreakerState,
		},
		"open with failures": {
			ctx: ctx, tenant: tenant, endpointID: endpointID, state: webhook.BreakerState{
				Status: webhook.BreakerOpen, Failures: 2, OpenedAt: time.Now(), OpenFor: time.Second,
			},
			wantErr: webhook.ErrInvalidBreakerState,
		},
		"open without cooldown": {
			ctx: ctx, tenant: tenant, endpointID: endpointID, state: webhook.BreakerState{
				Status: webhook.BreakerOpen, OpenedAt: time.Now(),
			},
			wantErr: webhook.ErrInvalidBreakerState,
		},
		"closed with open time": {
			ctx: ctx, tenant: tenant, endpointID: endpointID, state: webhook.BreakerState{
				Status: webhook.BreakerClosed, OpenedAt: time.Now(),
			},
			wantErr: webhook.ErrInvalidBreakerState,
		},
		"unknown status": {
			ctx: ctx, tenant: tenant, endpointID: endpointID,
			state: webhook.BreakerState{Status: "bogus"}, wantErr: webhook.ErrInvalidBreakerState,
		},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			var err error
			if name == "nil load context" || name == "empty load tenant" || name == "invalid load id" {
				_, err = store.Breaker(testCase.ctx, testCase.tenant, testCase.endpointID)
			} else {
				_, err = store.SaveBreaker(testCase.ctx, testCase.tenant, testCase.endpointID, testCase.expected, testCase.state)
			}
			if testCase.ctx == nil {
				if err == nil {
					t.Fatal("breaker call with nil context returned no error")
				}
				return
			}
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("breaker error = %v, want %v", err, testCase.wantErr)
			}
		})
	}
}
