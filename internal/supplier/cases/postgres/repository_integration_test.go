package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/supplier/cases"
	"github.com/sanskarpan/keel/internal/supplier/intake"
	intakepg "github.com/sanskarpan/keel/internal/supplier/intake/postgres"
)

func integrationRoleDB(t *testing.T, dsn, role, password string) *sql.DB {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	parsed.User = url.UserPassword(role, password)
	db, err := sql.Open("pgx", parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(4)
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		t.Fatalf("connect with %s role: %v", role, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestPostgreSQLSupplierCaseEvidenceAndWorkflowIntentLifecycle(t *testing.T) {
	appDSN, workerDSN := os.Getenv("KEEL_TEST_DATABASE_URL"), os.Getenv("KEEL_TEST_FILE_PROCESSOR_DATABASE_URL")
	if appDSN == "" || workerDSN == "" {
		t.Skip("set app and file-processor PostgreSQL URLs to run supplier case integration tests")
	}
	appDB := integrationRoleDB(t, appDSN, "keel_local_app", "keel-app-local-only")
	workerDB := integrationRoleDB(t, workerDSN, "keel_local_file_processor", "keel-file-processor-local-only")
	repo, err := New(appDB)
	if err != nil {
		t.Fatal(err)
	}
	intakeApp, err := intakepg.New(appDB)
	if err != nil {
		t.Fatal(err)
	}
	intakeWorker, err := intakepg.New(workerDB)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tenant, _ := tenancy.ParseTenantID("11111111-1111-4111-8111-111111111111")
	other, _ := tenancy.ParseTenantID("22222222-2222-4222-8222-222222222222")
	policyID, supplierID := testUUID(t), testUUID(t)
	policy := cases.Policy{TenantID: string(tenant), PolicyID: policyID, Version: 1, Name: "Standard review", Deadline: 48 * time.Hour, RequiredEvidence: []string{"tax"}, Steps: []cases.ReviewStep{{Key: "risk-review", Role: "risk:reviewer"}, {Key: "procurement-review", Role: "procurement:reviewer", DependsOn: []string{"risk-review"}}}}
	published, err := repo.PublishPolicy(ctx, tenant, policy, "principal:buyer-1")
	if err != nil {
		t.Fatal(err)
	}
	if published.PublishedAt.IsZero() || published.Digest == "" {
		t.Fatal("policy was not published and hashed")
	}
	replayedPolicy, err := repo.PublishPolicy(ctx, tenant, policy, "principal:buyer-1")
	if err != nil || replayedPolicy.Digest != published.Digest {
		t.Fatalf("identical policy retry did not return its immutable version: policy=%+v err=%v", replayedPolicy, err)
	}
	createKey := testUUID(t)
	created, err := repo.Create(ctx, tenant, createKey, supplierID, policyID, 1, "principal:buyer-1")
	if err != nil {
		t.Fatal(err)
	}
	caseID := created.CaseID
	createdAgain, err := repo.Create(ctx, tenant, createKey, supplierID, policyID, 1, "principal:buyer-1")
	if err != nil || createdAgain.CaseID != created.CaseID || createdAgain.Version != 1 {
		t.Fatalf("idempotent case retry mismatch: case=%+v err=%v", createdAgain, err)
	}
	if _, err := repo.Create(ctx, tenant, createKey, testUUID(t), policyID, 1, "principal:buyer-1"); !errors.Is(err, ErrConflict) {
		t.Fatalf("idempotency key with different request error=%v", err)
	}
	if created.Version != 1 || created.Status != cases.Collecting || created.DeadlineAt.Sub(created.CreatedAt) != 48*time.Hour {
		t.Fatalf("unexpected created case: %+v", created)
	}
	if _, err := repo.Get(ctx, other, caseID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant case read error=%v", err)
	}

	// Use the actual K2.1 invitation/upload/file-processor path to create eligible evidence.
	now := time.Now().UTC().Truncate(time.Microsecond)
	invitationID, uploadID := testUUID(t), testUUID(t)
	recipient := sha256.Sum256([]byte(testUUID(t)))
	secret, err := intake.NewSecret(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := intakeApp.IssueInvitation(ctx, tenant, invitationID, caseID, supplierID, secret, recipient, "principal:buyer-1", now, now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, session, err := intakeApp.AcceptInvitation(ctx, tenant, secret, testUUID(t), now, nil)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("verified tax evidence\n")
	sum := sha256.Sum256(data)
	metadata := intake.UploadMetadata{Filename: "tax.txt", ContentType: string(intake.FormatText), Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}
	if _, _, err := intakeApp.CreateUpload(ctx, tenant, session, uploadID, uploadID, metadata, now, now.Add(10*time.Minute), bytesOf(0x31, 32)); err != nil {
		t.Fatal(err)
	}
	if err := intakeApp.MarkUploaded(ctx, tenant, uploadID, invitationID, metadata.Size, metadata.SHA256, intake.FormatText, now); err != nil {
		t.Fatal(err)
	}
	job, err := intakeWorker.ClaimNext(ctx, tenant, "case-test-worker", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	document, err := intake.Process(ctx, job.Metadata, bytesReader(data), testScanner{}, testExtractor("normalized tax evidence"))
	if err != nil {
		t.Fatal(err)
	}
	if err := intakeWorker.Complete(ctx, job, testUUID(t), document, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	withEvidence, err := repo.AttachEvidence(ctx, tenant, caseID, testUUID(t), "tax-document", "tax", uploadID, "principal:buyer-1")
	if err != nil {
		t.Fatal(err)
	}
	if withEvidence.Version != 2 || withEvidence.EvidenceEpoch != 1 {
		t.Fatalf("unexpected evidence revision: %+v", withEvidence)
	}
	view, err := repo.Get(ctx, tenant, caseID)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Evidence) != 1 || len(view.Events) != 2 || view.Case.LastEventHash != view.Events[1].Hash {
		t.Fatalf("case history/evidence mismatch: %+v", view)
	}
	replayedEvidence, err := repo.AttachEvidence(ctx, tenant, caseID, testUUID(t), "tax-document", "tax", uploadID, "principal:buyer-1")
	if err != nil || replayedEvidence.Version != withEvidence.Version || replayedEvidence.EvidenceEpoch != withEvidence.EvidenceEpoch {
		t.Fatalf("idempotent evidence attach mismatch: case=%+v err=%v", replayedEvidence, err)
	}
	if _, err := repo.AttachEvidence(ctx, tenant, testUUID(t), testUUID(t), "other", "tax", uploadID, "principal:buyer-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-case evidence link error=%v", err)
	}

	submitted, err := repo.Submit(ctx, tenant, caseID, "principal:reviewer-1")
	if err != nil {
		t.Fatal(err)
	}
	if submitted.Status != cases.Submitted || submitted.Version != 3 {
		t.Fatalf("unexpected submitted case: %+v", submitted)
	}
	submittedAgain, err := repo.Submit(ctx, tenant, caseID, "principal:reviewer-1")
	if err != nil || submittedAgain.Version != submitted.Version {
		t.Fatalf("idempotent submit retry mismatch: case=%+v err=%v", submittedAgain, err)
	}
	view, err = repo.Get(ctx, tenant, caseID)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Events) != 3 || len(view.Evidence) != 1 || view.Case.Status != cases.Submitted {
		t.Fatalf("submitted case did not verify: %+v", view.Case)
	}
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if adminDSN == "" {
		t.Fatal("set KEEL_TEST_ADMIN_DATABASE_URL for reviewer authorization integration")
	}
	adminDB := integrationRoleDB(t, adminDSN, "postgres", "keel-local-only")
	if _, err := adminDB.ExecContext(ctx, `INSERT INTO keel_meta.supplier_case_reviewer_grants(tenant_id,principal_ref,role_key)
		VALUES ($1,'principal:reviewer-1','risk:reviewer'),($1,'principal:approver-1','risk:reviewer'),
		($1,'principal:approver-revoked','risk:reviewer'),($1,'principal:delegator-1','procurement:reviewer') ON CONFLICT (tenant_id,principal_ref,role_key)
		DO UPDATE SET granted_at=clock_timestamp(),revoked_at=NULL`, string(tenant)); err != nil {
		t.Fatal(err)
	}
	if _, err := adminDB.ExecContext(ctx, `UPDATE keel_meta.supplier_case_reviewer_grants SET revoked_at=clock_timestamp()
		WHERE tenant_id=$1 AND principal_ref='principal:approver-revoked'`, string(tenant)); err != nil {
		t.Fatal(err)
	}
	if err := tenancy.WithTenantTx(ctx, appDB, tenant, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.supplier_case_reviewer_grants(tenant_id,principal_ref,role_key) VALUES ($1,'principal:forged','risk:reviewer')`, string(tenant))
		return err
	}); err == nil {
		t.Fatal("case app unexpectedly managed reviewer grants")
	}
	if _, err := adminDB.ExecContext(ctx, `INSERT INTO keel_meta.supplier_case_delegations
		(tenant_id,delegation_id,delegator_ref,delegatee_ref,role_key,starts_at,expires_at)
		VALUES ($1,$2,'principal:delegator-1','principal:approver-2','procurement:reviewer',clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 day')`,
		string(tenant), testUUID(t)); err != nil {
		t.Fatal(err)
	}
	review := cases.ManualReviewData{ReviewID: testUUID(t), EvidenceID: view.Evidence[0].EvidenceID, Reason: "ambiguous registration date"}
	requestedReview, err := repo.RequestManualReview(ctx, tenant, caseID, review, "principal:approver-1")
	if err != nil || requestedReview.Status != cases.Submitted || requestedReview.Version != 4 {
		t.Fatalf("manual evidence review request failed or changed approval state: %+v err=%v", requestedReview, err)
	}
	requestedRetry, err := repo.RequestManualReview(ctx, tenant, caseID, review, "principal:approver-1")
	if err != nil || requestedRetry.Version != requestedReview.Version {
		t.Fatalf("manual evidence review request was not idempotent: %+v err=%v", requestedRetry, err)
	}
	review.Outcome, review.Reason = "confirmed", "document reviewed against original scan"
	resolvedReview, err := repo.ResolveManualReview(ctx, tenant, caseID, review, "principal:approver-1")
	if err != nil || resolvedReview.Status != cases.Submitted || resolvedReview.Version != 5 {
		t.Fatalf("manual evidence review resolution changed approval state: %+v err=%v", resolvedReview, err)
	}
	resolvedRetry, err := repo.ResolveManualReview(ctx, tenant, caseID, review, "principal:approver-1")
	if err != nil || resolvedRetry.Version != resolvedReview.Version {
		t.Fatalf("manual evidence review resolution was not idempotent: %+v err=%v", resolvedRetry, err)
	}
	if _, err := repo.Decide(ctx, tenant, caseID, cases.StepDecision{DecisionID: testUUID(t), StepKey: "risk-review", Actor: "principal:reviewer-1", Outcome: "approve"}); !errors.Is(err, cases.ErrConflict) {
		t.Fatalf("submitter self-approval should be refused: %v", err)
	}
	if _, err := repo.Decide(ctx, tenant, caseID, cases.StepDecision{DecisionID: testUUID(t), StepKey: "risk-review", Actor: "principal:approver-revoked", Outcome: "approve"}); err == nil {
		t.Fatal("revoked reviewer grant authorized a new decision")
	}
	decision := cases.StepDecision{DecisionID: testUUID(t), StepKey: "risk-review", Actor: "principal:approver-1", Outcome: "approve", Reason: "Verified against submitted policy."}
	afterFirst, err := repo.Decide(ctx, tenant, caseID, decision)
	if err != nil || afterFirst.Status != cases.Submitted || afterFirst.Version != 6 {
		t.Fatalf("first step decision failed: case=%+v err=%v", afterFirst, err)
	}
	decisionRetry, err := repo.Decide(ctx, tenant, caseID, decision)
	if err != nil || decisionRetry.Version != afterFirst.Version {
		t.Fatalf("identical decision retry did not return original result: %+v err=%v", decisionRetry, err)
	}
	if err := tenancy.WithTenantTx(ctx, appDB, tenant, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE keel_meta.supplier_cases SET case_state='approved',aggregate_version=aggregate_version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND case_id=$2`, string(tenant), caseID)
		return err
	}); err == nil {
		t.Fatal("incomplete approval plan reached approved state by direct snapshot mutation")
	}
	if _, err := repo.Decide(ctx, other, caseID, decision); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant decision error=%v", err)
	}
	if _, err := adminDB.ExecContext(ctx, `INSERT INTO keel_meta.supplier_case_delegations
		(tenant_id,delegation_id,delegator_ref,delegatee_ref,role_key,starts_at,expires_at)
		VALUES ($1,$2,'principal:delegator-1','principal:approver-expired','procurement:reviewer',clock_timestamp()-interval '2 minutes',clock_timestamp()-interval '1 minute')`,
		string(tenant), testUUID(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Decide(ctx, tenant, caseID, cases.StepDecision{DecisionID: testUUID(t), StepKey: "procurement-review", Actor: "principal:approver-expired", Outcome: "approve"}); err == nil {
		t.Fatal("expired delegation authorized a decision")
	}
	secondDecision := cases.StepDecision{DecisionID: testUUID(t), StepKey: "procurement-review", Actor: "principal:approver-2", Outcome: "approve"}
	approved, err := repo.Decide(ctx, tenant, caseID, secondDecision)
	if err != nil || approved.Status != cases.Approved || approved.Version != 7 {
		t.Fatalf("delegated final approval failed: %+v err=%v", approved, err)
	}
	if expiryRetry, err := repo.Expire(ctx, tenant, caseID); err != nil || expiryRetry.Status != cases.Approved || expiryRetry.Version != approved.Version {
		t.Fatalf("late expiry attempt changed a completed approval: %+v err=%v", expiryRetry, err)
	}
	view, err = repo.Get(ctx, tenant, caseID)
	if err != nil || view.Case.Status != cases.Approved || len(view.Events) != 7 {
		t.Fatalf("approved history mismatch: case=%+v events=%d err=%v", view.Case, len(view.Events), err)
	}

	cancelCase, err := repo.Create(ctx, tenant, testUUID(t), supplierID, policyID, 1, "principal:buyer-2")
	if err != nil {
		t.Fatal(err)
	}
	cancelToken, err := intake.NewSecret(nil)
	if err != nil {
		t.Fatal(err)
	}
	cancelInviteID := testUUID(t)
	if err := intakeApp.IssueInvitation(ctx, tenant, cancelInviteID, cancelCase.CaseID, supplierID, cancelToken, recipient, "principal:buyer-2", now, now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	cancelID, cancelReason := testUUID(t), "supplier withdrew the request"
	canceled, err := repo.Cancel(ctx, tenant, cancelCase.CaseID, cancelID, cancelReason, "principal:buyer-2")
	if err != nil || canceled.Status != cases.Canceled || canceled.Version != 2 {
		t.Fatalf("case cancellation failed: %+v err=%v", canceled, err)
	}
	if replay, err := repo.Cancel(ctx, tenant, cancelCase.CaseID, cancelID, cancelReason, "principal:buyer-2"); err != nil || replay.Version != canceled.Version {
		t.Fatalf("cancellation retry was not idempotent: %+v err=%v", replay, err)
	}
	if _, _, err := intakeApp.AcceptInvitation(ctx, tenant, cancelToken, testUUID(t), now, nil); !errors.Is(err, intake.ErrInvalidInvitation) {
		t.Fatalf("canceled case accepted its invitation: %v", err)
	}
	var invitationState string
	if err := adminDB.QueryRowContext(ctx, `SELECT invitation_state FROM keel_meta.supplier_invitations WHERE tenant_id=$1 AND invitation_id=$2`, string(tenant), cancelInviteID).Scan(&invitationState); err != nil || invitationState != "revoked" {
		t.Fatalf("cancellation did not revoke pending invitation: state=%s err=%v", invitationState, err)
	}

	var eventCount, intentCount int
	if err := tenancy.WithTenantTx(ctx, appDB, tenant, nil, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.supplier_case_events WHERE tenant_id=$1 AND case_id=$2`, string(tenant), caseID).Scan(&eventCount); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.supplier_workflow_intents WHERE tenant_id=$1 AND case_id=$2`, string(tenant), caseID).Scan(&intentCount)
	}); err != nil {
		t.Fatal(err)
	}
	if eventCount != 7 || intentCount != eventCount {
		t.Fatalf("case events=%d durable intents=%d, expected one intent per committed event", eventCount, intentCount)
	}
	if err := tenancy.WithTenantTx(ctx, appDB, tenant, nil, func(tx *sql.Tx) error {
		var previous []byte
		if err := tx.QueryRowContext(ctx, `SELECT last_event_hash FROM keel_meta.supplier_cases WHERE tenant_id=$1 AND case_id=$2`, string(tenant), caseID).Scan(&previous); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.supplier_case_events
			(tenant_id,case_id,aggregate_version,event_type,actor_ref,occurred_at,event_data,previous_hash,event_hash)
				VALUES ($1,$2,8,'supplier.case.approval-decided','principal:reviewer-1','2026-10-04 12:00:00+00','{}'::bytea,$3,$4)`,
			string(tenant), caseID, previous, make([]byte, 32))
		return err
	}); err == nil {
		t.Fatal("event without its workflow intent and snapshot transition committed")
	}
	if err := tenancy.WithTenantTx(ctx, appDB, tenant, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE keel_meta.supplier_cases SET case_state='rejected',aggregate_version=aggregate_version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND case_id=$2`, string(tenant), caseID)
		return err
	}); err == nil {
		t.Fatal("app role changed case state without an authorized event transition")
	}
	view, err = repo.Get(ctx, tenant, caseID)
	if err != nil || view.Case.Status != cases.Approved || view.Case.Version != 7 {
		t.Fatalf("failed snapshot mutation persisted: case=%+v err=%v", view.Case, err)
	}
	if err := tenancy.WithTenantTx(ctx, appDB, tenant, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE keel_meta.supplier_workflow_intents SET payload=payload WHERE tenant_id=$1 AND case_id=$2`, string(tenant), caseID)
		return err
	}); err == nil {
		t.Fatal("app role unexpectedly mutated append-only workflow intents")
	}
	if err := tenancy.WithTenantTx(ctx, appDB, tenant, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE keel_meta.supplier_case_decisions SET reason=reason WHERE tenant_id=$1 AND case_id=$2`, string(tenant), caseID)
		return err
	}); err == nil {
		t.Fatal("app role unexpectedly mutated append-only decisions")
	}
}

type testScanner struct{}

func (testScanner) Scan(context.Context, io.Reader) error { return nil }

type testExtractor string

func (e testExtractor) Extract(context.Context, intake.Format, io.Reader, int64) ([]byte, error) {
	return []byte(e), nil
}

func testUUID(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func bytesOf(value byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = value
	}
	return b
}

type dataReader struct{ data []byte }

func (r *dataReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}
func bytesReader(data []byte) *dataReader { return &dataReader{data: append([]byte(nil), data...)} }
