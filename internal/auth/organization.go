package auth

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

// Organization lifecycle bounds. Slugs are globally unique, DNS-safe handles;
// display names are bounded free text; regions are bounded deployment labels
// (the provisioned region set is a later K8.1 qualification).
const (
	MinOrgSlugLen   = 3
	MaxOrgSlugLen   = 63
	MaxOrgNameLen   = 128
	MaxOrgRegionLen = 32
)

// Invite windows are email-paced: an hour at minimum so delivery is never
// hopeless, seven days at most so stale invites cannot pile up.
const (
	MinInviteTTL = time.Hour
	MaxInviteTTL = 7 * 24 * time.Hour
)

var (
	// ErrInvalidOrganization reports a malformed organization field.
	ErrInvalidOrganization = errors.New("identity organization is invalid")
	// ErrInvalidMembership reports a malformed membership field.
	ErrInvalidMembership = errors.New("identity membership is invalid")
)

var (
	orgSlugPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
	orgRegionPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
)

// Organization roles. Owner transfer and demotion are a later K8.2 slice;
// this slice only creates owner memberships and adds admin/member seats.
const (
	OrgRoleOwner  = "owner"
	OrgRoleAdmin  = "admin"
	OrgRoleMember = "member"
)

// ValidateOrgSlug accepts one globally unique DNS-safe handle.
func ValidateOrgSlug(slug string) error {
	if len(slug) < MinOrgSlugLen || len(slug) > MaxOrgSlugLen || !orgSlugPattern.MatchString(slug) {
		return ErrInvalidOrganization
	}
	return nil
}

// ValidateOrgName accepts bounded display text.
func ValidateOrgName(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || len(trimmed) > MaxOrgNameLen || strings.ContainsAny(trimmed, "\r\n\x00") {
		return ErrInvalidOrganization
	}
	return nil
}

// ValidateOrgRegion accepts one bounded deployment label.
func ValidateOrgRegion(region string) error {
	if len(region) > MaxOrgRegionLen || !orgRegionPattern.MatchString(region) {
		return ErrInvalidOrganization
	}
	return nil
}

// ValidateOrgRole accepts one of the three fixed roles.
func ValidateOrgRole(role string) error {
	if role != OrgRoleOwner && role != OrgRoleAdmin && role != OrgRoleMember {
		return ErrInvalidMembership
	}
	return nil
}

// ValidateInviteTTL accepts one bounded invite window.
func ValidateInviteTTL(now, expires time.Time) error {
	if expires.IsZero() || expires.Before(now.Add(MinInviteTTL)) || expires.After(now.Add(MaxInviteTTL)) {
		return ErrInvalidRecord
	}
	return nil
}
