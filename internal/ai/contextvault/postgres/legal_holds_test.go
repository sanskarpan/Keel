package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func TestLegalHoldStoreRejectsInvalidIdentityScopeReasonAndReviewBounds(t *testing.T) {
	if _, err := NewLegalHoldStore(nil); err == nil {
		t.Fatal("nil legal hold database accepted")
	}
	store := &LegalHoldStore{db: &sql.DB{}}
	tenant := tenancy.TenantID("11111111-1111-4111-8111-111111111111")
	record := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	holdID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	actor := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	for _, test := range []struct {
		name string
		run  func() error
	}{
		{name: "zero actor", run: func() error {
			_, err := store.Create(context.Background(), tenant, record, 1, "00000000-0000-0000-0000-000000000000", LegalHoldLitigation, time.Second)
			return err
		}},
		{name: "invalid reason", run: func() error {
			_, err := store.Create(context.Background(), tenant, record, 1, actor, "free form", time.Second)
			return err
		}},
		{name: "too short review", run: func() error {
			_, err := store.Create(context.Background(), tenant, record, 1, actor, LegalHoldLitigation, MinLegalHoldReviewInterval-time.Nanosecond)
			return err
		}},
		{name: "too long review", run: func() error {
			_, err := store.Create(context.Background(), tenant, record, 1, actor, LegalHoldLitigation, MaxLegalHoldReviewInterval+time.Second)
			return err
		}},
		{name: "invalid decision", run: func() error {
			_, err := store.Review(context.Background(), tenant, holdID, actor, "decide-later", LegalHoldLitigation, time.Second)
			return err
		}},
		{name: "release interval", run: func() error {
			_, err := store.Review(context.Background(), tenant, holdID, actor, LegalHoldRelease, LegalHoldLitigation, time.Second)
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error=%v, want ErrInvalid", err)
			}
		})
	}
}
