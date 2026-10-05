package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const MaxErasureBacklogSample = 10_000

// ErasureBacklog contains bounded, scope-local counts. Counts are exact until
// the sample limit is reached; Truncated signals that reported counts are
// lower bounds. OldestOutstandingAgeSeconds uses database time and includes
// blocked jobs that still require operator action, but excludes completed jobs.
type ErasureBacklog struct {
	SampledAt      time.Time
	Fenced         int64
	CleanupPending int64
	Blocked        int64
	Due            int64
	Deferred       int64
	Leased         int64
	ExpiredLease   int64
	// OldestOutstandingAgeSeconds is a nonnegative database-time age. Keep this
	// as float64 seconds: valid PostgreSQL timestamps can span more than the
	// ~292-year range representable by time.Duration.
	OldestOutstandingAgeSeconds float64
	Truncated                   bool
}

// ReadErasureBacklog returns a bounded summary for one authorized tenant and
// visibility scope. It never returns job/source identities and uses a
// read-only, RLS-scoped transaction.
func (r *Repository) ReadErasureBacklog(ctx context.Context, tenant tenancy.TenantID, visibility string) (ErasureBacklog, error) {
	if err := validateErasureWorkerRepository(r, ctx); err != nil {
		return ErasureBacklog{}, err
	}
	s, err := newScope(tenant, visibility)
	if err != nil {
		return ErasureBacklog{}, err
	}
	var backlog ErasureBacklog
	var ageSeconds float64
	err = withScope(ctx, r.db, s, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		const query = `WITH sample_time AS MATERIALIZED (
			SELECT clock_timestamp() AS sampled_at
		), sample AS MATERIALIZED (
			SELECT j.state,j.requested_at,j.available_at,j.lease_owner,j.lease_until
			  FROM keel_meta.retrieval_erasure_jobs AS j
			 WHERE j.tenant_id=$1 AND j.visibility_key=$2
			   AND j.state IN ('fenced','cleanup_pending','blocked')
			 ORDER BY j.requested_at,j.job_id
			 LIMIT $3
		), summary AS (
			SELECT
				LEAST(count(*) FILTER (WHERE state='fenced'),$4)::bigint AS fenced,
				LEAST(count(*) FILTER (WHERE state='cleanup_pending'),$4)::bigint AS cleanup_pending,
				LEAST(count(*) FILTER (WHERE state='blocked'),$4)::bigint AS blocked,
				LEAST(count(*) FILTER (WHERE state IN ('fenced','cleanup_pending') AND lease_owner IS NULL AND available_at<=sampled_at),$4)::bigint AS due,
				LEAST(count(*) FILTER (WHERE state='cleanup_pending' AND lease_owner IS NULL AND available_at>sampled_at),$4)::bigint AS deferred,
				LEAST(count(*) FILTER (WHERE state='cleanup_pending' AND lease_owner IS NOT NULL AND lease_until>sampled_at),$4)::bigint AS leased,
				LEAST(count(*) FILTER (WHERE state='cleanup_pending' AND lease_owner IS NOT NULL AND lease_until<=sampled_at),$4)::bigint AS expired_lease,
				count(*) AS sampled_count,
				min(requested_at) AS oldest_requested_at
			  FROM sample CROSS JOIN sample_time
		)
		SELECT sample_time.sampled_at,summary.fenced,summary.cleanup_pending,summary.blocked,summary.due,
		       summary.deferred,summary.leased,summary.expired_lease,
		       COALESCE(GREATEST(EXTRACT(EPOCH FROM (sample_time.sampled_at-summary.oldest_requested_at))::double precision,
	                         0::double precision),0::double precision),
		       summary.sampled_count>$5
		  FROM sample_time CROSS JOIN summary`
		return tx.QueryRowContext(ctx, query, string(s.tenant), s.visibility,
			MaxErasureBacklogSample+1, MaxErasureBacklogSample, MaxErasureBacklogSample).
			Scan(&backlog.SampledAt, &backlog.Fenced, &backlog.CleanupPending, &backlog.Blocked, &backlog.Due,
				&backlog.Deferred, &backlog.Leased, &backlog.ExpiredLease, &ageSeconds, &backlog.Truncated)
	})
	if err != nil {
		return ErasureBacklog{}, fmt.Errorf("read scoped retrieval erasure backlog: %w", err)
	}
	backlog.OldestOutstandingAgeSeconds = ageSeconds
	return backlog, nil
}
