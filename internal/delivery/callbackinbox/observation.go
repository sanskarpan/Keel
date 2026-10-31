package callbackinbox

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ObservationOutcome is the durable claim outcome one callback delivery produced. It mirrors the
// claim function outcomes and never carries payload or receiver content.
type ObservationOutcome string

const (
	// ObservationApplied means the delivery applied its effect for the first time.
	ObservationApplied ObservationOutcome = "applied"
	// ObservationDuplicate means the delivery repeated an applied event.
	ObservationDuplicate ObservationOutcome = "duplicate"
	// ObservationConflict means the delivery conflicted with a recorded event.
	ObservationConflict ObservationOutcome = "conflict"
)

// validateObservation checks the outcome and the optional redelivery delay. A delay is only
// meaningful for redeliveries; first applications and conflicts carry none.
func validateObservation(outcome ObservationOutcome, delayMs sql.NullInt64) error {
	switch outcome {
	case ObservationApplied, ObservationDuplicate, ObservationConflict:
	default:
		return ErrInvalidCallback
	}
	if !delayMs.Valid {
		return nil
	}
	if outcome != ObservationDuplicate {
		return ErrInvalidCallback
	}
	if delayMs.Int64 < 0 || delayMs.Int64 > 9007199254740991 {
		return ErrInvalidCallback
	}
	return nil
}

// recordObservation appends one provider observation inside the caller's tenant transaction. It
// must run before the transaction commits so a rolled-back application leaves no observation.
func (i *Inbox) recordObservation(ctx context.Context, tx *sql.Tx, event VerifiedEvent, outcome ObservationOutcome, delayMs sql.NullInt64) error {
	if i == nil || i.db == nil {
		return errors.New("callback inbox database is required")
	}
	if ctx == nil {
		return errors.New("callback context is required")
	}
	if tx == nil {
		return errors.New("callback observation transaction is required")
	}
	if err := validateObservation(outcome, delayMs); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx,
		`SELECT r_observation_id FROM keel_meta.record_provider_callback_observation($1,$2,$3,$4)`,
		event.Provider, event.ProviderEventID, string(outcome), delayMs).
		Scan(new(int64)); err != nil {
		if strings.Contains(err.Error(), "provider observation request is invalid") {
			return ErrInvalidCallback
		}
		return fmt.Errorf("record provider callback observation: %w", err)
	}
	return nil
}

// redeliveryDelayMs measures whole milliseconds from a prior application, clamped at zero so
// clock skew never produces a negative delay.
func redeliveryDelayMs(appliedAt time.Time) sql.NullInt64 {
	delay := time.Since(appliedAt.UTC()) / time.Millisecond
	if delay < 0 {
		delay = 0
	}
	return sql.NullInt64{Int64: int64(delay), Valid: true}
}
