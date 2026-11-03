package auth

import "time"

// Lifecycle bounds fixed by this slice. Session and verification TTLs are
// bounded in both directions so an operator cannot mint an effectively
// permanent session or an instantly-expired verification window.
const (
	MinSessionTTL      = time.Minute
	MaxSessionTTL      = 30 * 24 * time.Hour
	MinVerificationTTL = 5 * time.Minute
	MaxVerificationTTL = 24 * time.Hour
)

// Session is a stored session row as judged by the caller. Expiry is checked
// against the caller's clock after the database read; a stored revocation is
// unconditional because this slice never schedules future revocations.
type Session struct {
	SessionID      string
	PrincipalID    string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	RevokedAt      time.Time
	PrincipalState string
}

// Valid reports whether the session is usable for a principal that is still
// active as of now. A stored revocation, an expired row or a principal that
// is not currently active all fail closed.
func (s Session) Valid(now time.Time) bool {
	if s.SessionID == "" || s.PrincipalID == "" {
		return false
	}
	if s.PrincipalState != PrincipalActive {
		return false
	}
	if !s.RevokedAt.IsZero() {
		return false
	}
	return now.Before(s.ExpiresAt)
}

// ValidateResetTTL accepts one bounded password reset window; it intentionally
// shares the verification bounds because an unused reset request is the same
// kind of one-shot capability. The caller clocks expiry checks against now.
func ValidateResetTTL(now, expires time.Time) error {
	return ValidateVerificationTTL(now, expires)
}

// ValidateSessionBounds accepts a caller-chosen TTL within the fixed window.
func ValidateSessionTTL(now, expires time.Time) error {
	if expires.IsZero() || expires.Before(now.Add(MinSessionTTL)) || expires.After(now.Add(MaxSessionTTL)) {
		return ErrInvalidRecord
	}
	return nil
}

// ValidateVerificationTTL accepts one bounded verification window.
func ValidateVerificationTTL(now, expires time.Time) error {
	if expires.IsZero() || expires.Before(now.Add(MinVerificationTTL)) || expires.After(now.Add(MaxVerificationTTL)) {
		return ErrInvalidRecord
	}
	return nil
}
