package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/supplier/intake"
)

func openRoleDB(t *testing.T, dsn, role, password string) *sql.DB {
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
	db.SetMaxOpenConns(2)
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		t.Fatalf("connect with %s role: %v", role, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestPostgreSQLSupplierInvitationAndUploadLifecycle(t *testing.T) {
	appDSN := os.Getenv("KEEL_TEST_DATABASE_URL")
	workerDSN := os.Getenv("KEEL_TEST_FILE_PROCESSOR_DATABASE_URL")
	if appDSN == "" || workerDSN == "" {
		t.Skip("set app and file-processor PostgreSQL URLs to run supplier intake integration tests")
	}
	appDB := openRoleDB(t, appDSN, "keel_local_app", "keel-app-local-only")
	workerDB := openRoleDB(t, workerDSN, "keel_local_file_processor", "keel-file-processor-local-only")
	appRepo, err := New(appDB)
	if err != nil {
		t.Fatal(err)
	}
	workerRepo, err := New(workerDB)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tenant, err := tenancy.ParseTenantID("11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	otherTenant, _ := tenancy.ParseTenantID("22222222-2222-4222-8222-222222222222")
	now := time.Now().UTC().Truncate(time.Microsecond)
	invitationID, caseID, supplierID := nextIntakeUUID(t), nextIntakeUUID(t), nextIntakeUUID(t)
	recipient, err := RecipientDigest("supplier@example.test", bytesOf(0x31, 32))
	if err != nil {
		t.Fatal(err)
	}
	inviteToken, err := intake.NewSecret(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := appRepo.IssueInvitation(ctx, tenant, invitationID, caseID, supplierID, inviteToken, recipient, "principal:buyer-1", now, now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := appRepo.AcceptInvitation(ctx, otherTenant, inviteToken, nextIntakeUUID(t), now, nil); err == nil {
		t.Fatal("invitation was accepted in a different tenant")
	}
	accepted, sessionToken, err := appRepo.AcceptInvitation(ctx, tenant, inviteToken, nextIntakeUUID(t), now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.State != "accepted" || accepted.CaseID != caseID || sessionToken == "" {
		t.Fatalf("unexpected accepted invitation: %+v", accepted)
	}
	if _, _, err := appRepo.AcceptInvitation(ctx, tenant, inviteToken, nextIntakeUUID(t), now, nil); err == nil {
		t.Fatal("single-use invitation was accepted a second time")
	}

	data := []byte("supplier evidence, version one\n")
	sum := sha256.Sum256(data)
	metadata := intake.UploadMetadata{Filename: "supplier-evidence.txt", ContentType: string(intake.FormatText), Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}
	uploadID := nextIntakeUUID(t)
	objectKey := uploadID
	capabilityKey := bytesOf(0x42, 32)
	sessionDigest, _ := intake.TokenDigest(sessionToken, "supplier-upload-session-v1")
	if err := tenancy.WithTenantTx(ctx, appDB, tenant, nil, func(tx *sql.Tx) error {
		var sessionCount, inviteCount int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.supplier_upload_sessions WHERE session_token_digest=$1 AND expires_at>$2 AND revoked_at IS NULL`, sessionDigest[:], now).Scan(&sessionCount); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.supplier_invitations WHERE invitation_id=$1 AND invitation_state='accepted' AND expires_at>$2 AND revoked_at IS NULL`, invitationID, now).Scan(&inviteCount); err != nil {
			return err
		}
		if sessionCount != 1 || inviteCount != 1 {
			t.Fatalf("before upload create: sessions=%d invitations=%d", sessionCount, inviteCount)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	upload, capability, err := appRepo.CreateUpload(ctx, tenant, sessionToken, uploadID, objectKey, metadata, now, now.Add(10*time.Minute), capabilityKey)
	if err != nil {
		t.Fatal(err)
	}
	if upload.State != "awaiting_upload" || capability == "" {
		t.Fatalf("unexpected upload capability response: state=%q", upload.State)
	}
	renewedCapability, err := appRepo.RenewCapability(ctx, tenant, sessionToken, uploadID, now.Add(time.Minute), now.Add(11*time.Minute), capabilityKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := appRepo.RenewCapability(ctx, otherTenant, sessionToken, uploadID, now.Add(time.Minute), now.Add(11*time.Minute), capabilityKey); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant capability renewal error=%v", err)
	}
	capability = renewedCapability
	loadedInvitation, loadedMetadata, capabilityExpiry, err := appRepo.LoadUploadMetadata(ctx, tenant, uploadID, now)
	if err != nil || loadedInvitation != invitationID || loadedMetadata.Filename != "evidence.txt" || loadedMetadata.SHA256 != metadata.SHA256 || !capabilityExpiry.Equal(now.Add(11*time.Minute).Truncate(time.Second)) {
		t.Fatalf("stored upload claims were not loaded safely: invitation=%s metadata=%+v expiry=%s err=%v", loadedInvitation, loadedMetadata, capabilityExpiry, err)
	}
	claim, err := intake.VerifyUploadCapability(capability, capabilityKey, now.Add(2*time.Minute), string(tenant), uploadID, metadata)
	if err != nil || claim.UploadID != uploadID {
		t.Fatalf("upload capability did not verify: claim=%+v err=%v", claim, err)
	}
	if err := appRepo.MarkUploaded(ctx, tenant, uploadID, invitationID, metadata.Size+1, metadata.SHA256, intake.FormatText, now); err == nil {
		t.Fatal("upload with a mismatched object length was finalized")
	}
	if err := appRepo.MarkUploaded(ctx, tenant, uploadID, invitationID, metadata.Size, metadata.SHA256, intake.FormatText, now); err != nil {
		t.Fatal(err)
	}

	job, err := workerRepo.ClaimNext(ctx, tenant, "file-worker-1", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if job.UploadID != uploadID || job.ClaimEpoch != 1 || job.Metadata.Filename != "evidence.txt" {
		t.Fatalf("unexpected leased job: %+v", job)
	}
	document, err := intake.Process(ctx, job.Metadata, bytesReader(data), cleanScanner{}, fixedExtractor("normalized evidence"))
	if err != nil {
		t.Fatal(err)
	}
	if err := workerRepo.Complete(ctx, job, nextIntakeUUID(t), document, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := workerRepo.Complete(ctx, job, nextIntakeUUID(t), document, now.Add(2*time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale lease completion error = %v, want conflict", err)
	}

	var state string
	if err := tenancy.WithTenantTx(ctx, appDB, tenant, nil, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT upload_state FROM keel_meta.supplier_uploads WHERE tenant_id=$1 AND upload_id=$2`, string(tenant), uploadID).Scan(&state)
	}); err != nil {
		t.Fatal(err)
	}
	if state != "extracted" {
		t.Fatalf("stored upload state = %q, want extracted", state)
	}
	var visible int
	if err := tenancy.WithTenantTx(ctx, appDB, otherTenant, nil, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.supplier_uploads WHERE upload_id=$1`, uploadID).Scan(&visible)
	}); err != nil {
		t.Fatal(err)
	}
	if visible != 0 {
		t.Fatalf("another tenant saw %d upload rows", visible)
	}
	for range 4 {
		pendingID := nextIntakeUUID(t)
		if _, _, err := appRepo.CreateUpload(ctx, tenant, sessionToken, pendingID, pendingID, metadata, now, now.Add(5*time.Minute), capabilityKey); err != nil {
			t.Fatalf("create pending upload: %v", err)
		}
	}
	blockedID := nextIntakeUUID(t)
	if _, _, err := appRepo.CreateUpload(ctx, tenant, sessionToken, blockedID, blockedID, metadata, now, now.Add(5*time.Minute), capabilityKey); !errors.Is(err, ErrConflict) {
		t.Fatalf("fifth active upload was not rejected by the invitation quota: %v", err)
	}
	newTime := now.Add(11 * time.Minute)
	retryID := nextIntakeUUID(t)
	if _, _, err := appRepo.CreateUpload(ctx, tenant, sessionToken, retryID, retryID, metadata, newTime, newTime.Add(5*time.Minute), capabilityKey); err != nil {
		t.Fatalf("expired, never-uploaded attempts kept the supplier quota full: %v", err)
	}
	var expired int
	if err := tenancy.WithTenantTx(ctx, appDB, tenant, nil, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.supplier_uploads WHERE tenant_id=$1 AND invitation_id=$2 AND upload_state='expired'`, string(tenant), invitationID).Scan(&expired)
	}); err != nil {
		t.Fatal(err)
	}
	if expired != 4 {
		t.Fatalf("expired pending capabilities = %d, want 4", expired)
	}
}

type byteSliceReader struct{ data []byte }

func (r *byteSliceReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}
func bytesReader(data []byte) *byteSliceReader {
	return &byteSliceReader{data: append([]byte(nil), data...)}
}
func bytesOf(value byte, size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = value
	}
	return b
}
func nextIntakeUUID(t *testing.T) string {
	t.Helper()
	value, err := UUID(nil)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

type cleanScanner struct{}

func (cleanScanner) Scan(context.Context, io.Reader) error { return nil }

type fixedExtractor string

func (e fixedExtractor) Extract(context.Context, intake.Format, io.Reader, int64) ([]byte, error) {
	return []byte(e), nil
}
