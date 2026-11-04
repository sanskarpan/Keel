package auth

import (
	"strings"
	"testing"
	"time"
)

func TestOrgValidation(t *testing.T) {
	for _, ok := range []string{"acme", "acme-corp-1", strings.Repeat("a", MaxOrgSlugLen)} {
		if err := ValidateOrgSlug(ok); err != nil {
			t.Fatalf("slug %q: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "ab", strings.Repeat("a", MaxOrgSlugLen+1), "Acme", "-lead", "trail-",
		"has space", "has_underscore", "UPPER",
	} {
		if err := ValidateOrgSlug(bad); err == nil {
			t.Fatalf("slug accepted: %q", bad)
		}
	}
	if err := ValidateOrgName("Acme Corporation"); err != nil {
		t.Fatalf("name: %v", err)
	}
	for _, bad := range []string{"", "  ", strings.Repeat("n", MaxOrgNameLen+1), "line\nbreak"} {
		if err := ValidateOrgName(bad); err == nil {
			t.Fatalf("name accepted: %q", bad)
		}
	}
	for _, ok := range []string{"home", "eu-west-1", "modal-lhr"} {
		if err := ValidateOrgRegion(ok); err != nil {
			t.Fatalf("region %q: %v", ok, err)
		}
	}
	for _, bad := range []string{"Home", "1west", "has space", strings.Repeat("r", MaxOrgRegionLen+1)} {
		if err := ValidateOrgRegion(bad); err == nil {
			t.Fatalf("region accepted: %q", bad)
		}
	}
	for _, ok := range []string{OrgRoleOwner, OrgRoleAdmin, OrgRoleMember} {
		if err := ValidateOrgRole(ok); err != nil {
			t.Fatalf("role %q: %v", ok, err)
		}
	}
	if err := ValidateOrgRole("superadmin"); err == nil {
		t.Fatal("unknown role accepted")
	}
}

func TestInviteTTLBounds(t *testing.T) {
	now := time.Date(2026, time.November, 2, 12, 0, 0, 0, time.UTC)
	if err := ValidateInviteTTL(now, now.Add(24*time.Hour)); err != nil {
		t.Fatalf("valid window: %v", err)
	}
	if err := ValidateInviteTTL(now, now.Add(30*time.Minute)); err == nil {
		t.Fatal("under-min window accepted")
	}
	if err := ValidateInviteTTL(now, now.Add(30*24*time.Hour)); err == nil {
		t.Fatal("over-max window accepted")
	}
}
