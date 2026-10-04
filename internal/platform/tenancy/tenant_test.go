package tenancy

import "testing"

func TestParseTenantID(t *testing.T) {
	valid, err := ParseTenantID("11111111-1111-4111-8111-111111111111")
	if err != nil || valid == "" {
		t.Fatalf("expected canonical tenant UUID, got %q, %v", valid, err)
	}
	for _, value := range []string{"", "tenant-a", "11111111111141118111111111111111", "11111111-1111-4111-8111-11111111111g"} {
		if _, err := ParseTenantID(value); err == nil {
			t.Errorf("ParseTenantID(%q) unexpectedly succeeded", value)
		}
	}
}
