package webhook

import (
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const (
	// MaxReplayReasonBytes bounds the operator-supplied replay justification in bytes.
	MaxReplayReasonBytes = 512
)

var (
	// ErrReplayConflict means a replay request contradicts a recorded replay or delivery.
	ErrReplayConflict = errors.New("webhook replay request conflicts with an existing replay")

	replayIDPattern         = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	replayDeliveryIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	replayActorPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$`)
)

// ReplayRequest is one operator's bounded request to replay a failed delivery. The request carries
// the audit identity and justification; it never carries receiver content or endpoint secrets.
type ReplayRequest struct {
	Tenant      tenancy.TenantID
	ReplayID    string
	DeliveryID  string
	RequestedBy string
	Reason      string
}

// Validate checks the tenant, both identities, the audit actor and the bounded reason. Every invalid
// field reports ErrInvalidReplay so a caller cannot distinguish rejected values.
func (r ReplayRequest) Validate() error {
	if string(r.Tenant) == "" || string(r.Tenant) == zeroTenant {
		return ErrInvalidReplay
	}
	if _, err := tenancy.ParseTenantID(string(r.Tenant)); err != nil {
		return ErrInvalidReplay
	}
	if err := ValidateReplayID(r.ReplayID); err != nil {
		return err
	}
	if err := ValidateReplayDeliveryID(r.DeliveryID); err != nil {
		return err
	}
	if !replayActorPattern.MatchString(r.RequestedBy) {
		return ErrInvalidReplay
	}
	if err := validateReplayReason(r.Reason); err != nil {
		return err
	}
	return nil
}

// ValidateReplayID checks the caller-supplied replay identity.
func ValidateReplayID(replayID string) error {
	if !replayIDPattern.MatchString(replayID) {
		return ErrInvalidReplay
	}
	return nil
}

// ValidateReplayDeliveryID checks the delivery identity a replay selects.
func ValidateReplayDeliveryID(deliveryID string) error {
	if !replayDeliveryIDPattern.MatchString(deliveryID) {
		return ErrInvalidReplay
	}
	return nil
}

func validateReplayReason(reason string) error {
	if !utf8.ValidString(reason) {
		return ErrInvalidReplay
	}
	if strings.TrimSpace(reason) != reason {
		return ErrInvalidReplay
	}
	if len(reason) < 1 || len(reason) > MaxReplayReasonBytes {
		return ErrInvalidReplay
	}
	for index := 0; index < len(reason); index++ {
		if reason[index] < 0x20 || reason[index] == 0x7f {
			return ErrInvalidReplay
		}
	}
	return nil
}
