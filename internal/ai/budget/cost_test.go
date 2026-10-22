package budget

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"testing"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

// tenancyIDForTest returns a validated tenant identity for the reader validation cases.
func tenancyIDForTest() tenancy.TenantID {
	tenant, err := tenancy.ParseTenantID(uuid.NewString())
	if err != nil {
		panic(err)
	}
	return tenant
}

func TestCostReaderRequiresDatabase(t *testing.T) {
	if _, err := NewCostReader(nil); err == nil {
		t.Fatal("a cost reader was created without a database")
	}
}

func TestCostReaderRejectsUnvalidatedScope(t *testing.T) {
	reader := &CostReader{db: &sql.DB{}}
	ctx := context.Background()
	if _, err := reader.CostBreakdown(ctx, "not-a-tenant", ""); !errors.Is(err, ErrCostUnavailable) {
		t.Fatalf("an unvalidated tenant returned %v", err)
	}
	if _, err := reader.CostEntries(ctx, "not-a-tenant", "", 10); !errors.Is(err, ErrCostUnavailable) {
		t.Fatalf("an unvalidated tenant returned %v", err)
	}
}

func TestCostReaderRejectsUnvalidatedPeriod(t *testing.T) {
	reader := &CostReader{db: &sql.DB{}}
	ctx := context.Background()
	tenant := tenancyIDForTest()
	if _, err := reader.CostBreakdown(ctx, tenant, "not-a-period"); !errors.Is(err, ErrCostUnavailable) {
		t.Fatalf("an unvalidated period returned %v", err)
	}
	if _, err := reader.CostEntries(ctx, tenant, "not-a-period", 10); !errors.Is(err, ErrCostUnavailable) {
		t.Fatalf("an unvalidated period returned %v", err)
	}
}

func TestCostReaderRejectsUnboundedEntryLimit(t *testing.T) {
	reader := &CostReader{db: &sql.DB{}}
	ctx := context.Background()
	tenant := tenancyIDForTest()
	for _, limit := range []int{0, -1, MaxCostEntries + 1} {
		if _, err := reader.CostEntries(ctx, tenant, "", limit); err == nil {
			t.Fatalf("limit %d was accepted", limit)
		}
	}
}

func TestCostAmountRejectsUnrepresentableValues(t *testing.T) {
	cases := map[string]string{
		"negative":     "-1",
		"not a number": "twelve",
		"overflow":     "9223372036854775808",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := costAmount(raw); !errors.Is(err, ErrCostRange) {
				t.Fatalf("value %q returned %v", raw, err)
			}
		})
	}
}

func TestCostAmountAcceptsBoundedValues(t *testing.T) {
	for _, raw := range []string{"0", " 42 ", "9223372036854775807"} {
		value, err := costAmount(raw)
		if err != nil {
			t.Fatalf("value %q returned %v", raw, err)
		}
		if value < 0 || value > math.MaxInt64 {
			t.Fatalf("value %q produced %d", raw, value)
		}
	}
}
