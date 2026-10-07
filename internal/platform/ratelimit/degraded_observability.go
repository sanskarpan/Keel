package ratelimit

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// DegradedWindowStatus is a home-region snapshot from PostgreSQL. It contains
// no outage identifier, tenant, route, or request data and is safe to export as
// process-level metrics. SecondsUntilExpiry and ObservedAt use database time.
type DegradedWindowStatus struct {
	Present            bool
	Active             bool
	AdmissionOpen      bool
	SecondsUntilExpiry float64
	ObservedAt         time.Time
	LastRecoveredAt    *time.Time
}

// ObserveDegradedWindowStatus reads one home-region recovery window through
// the rate-control-only database function and publishes the resulting snapshot
// to the metrics extension. Callers should refresh it periodically; a failed
// refresh leaves the last successful snapshot in place and returns an error.
func ObserveDegradedWindowStatus(ctx context.Context, rateControlDB *sql.DB, region string, metrics *DegradedMetrics) error {
	if ctx == nil || rateControlDB == nil || metrics == nil || !validIdentifier(region, maxRegionLength) {
		return ErrInvalidConfig
	}
	var status DegradedWindowStatus
	var recoveredAt sql.NullTime
	err := rateControlDB.QueryRowContext(ctx, `
		SELECT window_present,active,admission_open,seconds_until_expiry,observed_at,recovered_at
		FROM keel_meta.read_rate_limit_degraded_window_state($1)`, region).Scan(
		&status.Present, &status.Active, &status.AdmissionOpen, &status.SecondsUntilExpiry,
		&status.ObservedAt, &recoveredAt)
	if err != nil {
		return fmt.Errorf("read degraded window status: %w", err)
	}
	if !status.Present || !recoveredAt.Valid {
		status.LastRecoveredAt = nil
	} else {
		recovered := recoveredAt.Time
		status.LastRecoveredAt = &recovered
	}
	metrics.setWindowStatus(status)
	return nil
}

// RunDegradedWindowStatusRefresh periodically refreshes the process-local
// status snapshot using the restricted rate-control database function. It
// performs an initial read before waiting for the first tick. Transient read
// failures increment a fixed, unlabeled counter and leave the last successful
// snapshot intact; the snapshot's database timestamp lets scrapers detect
// staleness. Cancellation is a graceful stop.
func RunDegradedWindowStatusRefresh(ctx context.Context, rateControlDB *sql.DB, region string, metrics *DegradedMetrics, interval, queryTimeout time.Duration) error {
	if ctx == nil || rateControlDB == nil || metrics == nil || !validIdentifier(region, maxRegionLength) || interval <= 0 || queryTimeout <= 0 || queryTimeout > interval {
		return ErrInvalidConfig
	}
	return runDegradedWindowStatusRefresh(ctx, interval, queryTimeout, func(callCtx context.Context) error {
		return ObserveDegradedWindowStatus(callCtx, rateControlDB, region, metrics)
	}, metrics.recordWindowStatusRefreshError)
}

func runDegradedWindowStatusRefresh(ctx context.Context, interval, queryTimeout time.Duration, observe func(context.Context) error, onError func()) error {
	if ctx == nil || observe == nil || onError == nil || interval <= 0 || queryTimeout <= 0 || queryTimeout > interval {
		return ErrInvalidConfig
	}
	if ctx.Err() != nil {
		return nil
	}
	refresh := func() {
		callCtx, cancel := context.WithTimeout(ctx, queryTimeout)
		defer cancel()
		if err := observe(callCtx); err != nil && ctx.Err() == nil {
			onError()
		}
	}
	refresh()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			refresh()
		}
	}
}

func (m *DegradedMetrics) setWindowStatus(status DegradedWindowStatus) {
	m.setWindowStatusAt(status, time.Now())
}

func (m *DegradedMetrics) setWindowStatusAt(status DegradedWindowStatus, refreshedAt time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	statusCopy := status
	if status.LastRecoveredAt != nil {
		recoveredAt := *status.LastRecoveredAt
		statusCopy.LastRecoveredAt = &recoveredAt
	}
	m.windowStatus = &statusCopy
	m.windowStatusRefreshedAt = refreshedAt
	m.mu.Unlock()
}

func (m *DegradedMetrics) recordWindowStatusRefreshError() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.windowStatusRefreshErrors++
	m.mu.Unlock()
}

// WindowStatusObserved reports whether a successful database-backed snapshot
// is available for readiness checks. It does not imply that the snapshot is
// fresh; the exported database timestamp is the staleness signal.
func (m *DegradedMetrics) WindowStatusObserved() bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.windowStatus != nil
}

// WindowStatusFresh reports whether a successful snapshot is recent according
// to the observer process clock. The database timestamp remains available as
// an exported gauge, but readiness must not depend on cross-host clock sync.
func (m *DegradedMetrics) WindowStatusFresh(now time.Time, maxAge time.Duration) bool {
	if m == nil || maxAge <= 0 {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.windowStatus == nil || m.windowStatusRefreshedAt.IsZero() || now.Before(m.windowStatusRefreshedAt) {
		return false
	}
	return now.Sub(m.windowStatusRefreshedAt) <= maxAge
}

func writeDegradedWindowMetrics(b *strings.Builder, status *DegradedWindowStatus) {
	b.WriteString("# HELP keel_rate_limit_degraded_window_status_observed Whether a database-backed window status snapshot has been observed.\n")
	b.WriteString("# TYPE keel_rate_limit_degraded_window_status_observed gauge\n")
	b.WriteString("# HELP keel_rate_limit_degraded_window_present Whether a degraded admission window exists for the configured home region.\n")
	b.WriteString("# TYPE keel_rate_limit_degraded_window_present gauge\n")
	b.WriteString("# HELP keel_rate_limit_degraded_window_active Whether the degraded window remains fenced pending verified Redis recovery.\n")
	b.WriteString("# TYPE keel_rate_limit_degraded_window_active gauge\n")
	b.WriteString("# HELP keel_rate_limit_degraded_admission_window_open Whether new fallback admissions are still within the 60-second window.\n")
	b.WriteString("# TYPE keel_rate_limit_degraded_admission_window_open gauge\n")
	b.WriteString("# HELP keel_rate_limit_degraded_window_seconds_until_expiry Seconds until the admission window closes, according to PostgreSQL time.\n")
	b.WriteString("# TYPE keel_rate_limit_degraded_window_seconds_until_expiry gauge\n")
	b.WriteString("# HELP keel_rate_limit_degraded_window_last_observed_timestamp_seconds Database timestamp of the latest successful window status read.\n")
	b.WriteString("# TYPE keel_rate_limit_degraded_window_last_observed_timestamp_seconds gauge\n")
	b.WriteString("# HELP keel_rate_limit_degraded_window_last_recovered_timestamp_seconds Database timestamp when Redis recovery last closed the window, or zero when absent.\n")
	b.WriteString("# TYPE keel_rate_limit_degraded_window_last_recovered_timestamp_seconds gauge\n")
	if status == nil {
		b.WriteString("keel_rate_limit_degraded_window_status_observed 0\n")
		return
	}
	b.WriteString("keel_rate_limit_degraded_window_status_observed 1\n")
	writeBoolGauge(b, "keel_rate_limit_degraded_window_present", status.Present)
	writeBoolGauge(b, "keel_rate_limit_degraded_window_active", status.Active)
	writeBoolGauge(b, "keel_rate_limit_degraded_admission_window_open", status.AdmissionOpen)
	fmt.Fprintf(b, "keel_rate_limit_degraded_window_seconds_until_expiry %.6f\n", status.SecondsUntilExpiry)
	fmt.Fprintf(b, "keel_rate_limit_degraded_window_last_observed_timestamp_seconds %.6f\n", float64(status.ObservedAt.UnixNano())/float64(time.Second))
	recoveredAtSeconds := float64(0)
	if status.LastRecoveredAt != nil {
		recoveredAtSeconds = float64(status.LastRecoveredAt.UnixNano()) / float64(time.Second)
	}
	fmt.Fprintf(b, "keel_rate_limit_degraded_window_last_recovered_timestamp_seconds %.6f\n", recoveredAtSeconds)
}

func writeBoolGauge(b *strings.Builder, name string, value bool) {
	if value {
		fmt.Fprintf(b, "%s 1\n", name)
		return
	}
	fmt.Fprintf(b, "%s 0\n", name)
}
