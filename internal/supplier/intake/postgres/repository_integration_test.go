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
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/retrieval/contracts"
	"github.com/sanskarpan/keel/internal/retrieval/hybrid"
	"github.com/sanskarpan/keel/internal/retrieval/index"
	retrievalpg "github.com/sanskarpan/keel/internal/retrieval/postgres"
	citationintake "github.com/sanskarpan/keel/internal/retrieval/source/intake"
	"github.com/sanskarpan/keel/internal/supplier/cases"
	casepg "github.com/sanskarpan/keel/internal/supplier/cases/postgres"
	"github.com/sanskarpan/keel/internal/supplier/intake"
)

type testLegalHoldAuthority struct {
	clear    bool
	released bool
	actorID  uuid.UUID
}

type failOnceObjectDeleter struct {
	store   *intake.LocalStore
	failKey string
	failed  bool
}

func (d *failOnceObjectDeleter) Delete(ctx context.Context, key string) error {
	if key == d.failKey && !d.failed {
		d.failed = true
		return errors.New("synthetic object-store interruption")
	}
	return d.store.Delete(ctx, key)
}

func (a *testLegalHoldAuthority) AcquireClearance(_ context.Context, fence citationintake.ErasureFence) (citationintake.HoldClearance, error) {
	if !a.clear || fence.JobID == uuid.Nil || fence.DocumentVersionID == uuid.Nil || fence.LeaseEpoch < 1 {
		return citationintake.HoldClearance{}, errors.New("synthetic hold authority denied clearance")
	}
	if a.actorID == uuid.Nil {
		a.actorID = uuid.New()
	}
	return citationintake.HoldClearance{
		DecisionActorID: a.actorID,
		EvidenceSHA256:  sha256.Sum256([]byte("synthetic serialized legal-hold clearance")),
		Release: func() error {
			a.released = true
			return nil
		},
	}, nil
}

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
	invitationID, supplierID := nextIntakeUUID(t), nextIntakeUUID(t)
	policyID := nextIntakeUUID(t)
	casesRepo, err := casepg.New(appDB)
	if err != nil {
		t.Fatal(err)
	}
	policy := cases.Policy{TenantID: string(tenant), PolicyID: policyID, Version: 1, Name: "Supplier intake integration", Deadline: 4 * time.Hour, Steps: []cases.ReviewStep{{Key: "review", Role: "risk:reviewer"}}}
	if _, err := casesRepo.PublishPolicy(ctx, tenant, policy, "principal:buyer-1"); err != nil {
		t.Fatal(err)
	}
	createdCase, err := casesRepo.Create(ctx, tenant, nextIntakeUUID(t), supplierID, policyID, 1, "principal:buyer-1")
	if err != nil {
		t.Fatal(err)
	}
	caseID := createdCase.CaseID
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
	outputKey := nextIntakeUUID(t)
	objects, err := intake.NewLocalStore(filepath.Join(t.TempDir(), "objects"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = objects.Close() })
	if _, _, err := objects.Put(ctx, objectKey, bytesReader(data), intake.MaxUploadBytes); err != nil {
		t.Fatalf("persist raw upload object: %v", err)
	}
	storedBytes, storedDigest, err := objects.Put(ctx, outputKey, bytesReader(document.Text), intake.MaxExtractedSize)
	if err != nil || storedBytes != int64(len(document.Text)) || storedDigest != document.TextSHA256 {
		t.Fatalf("persist extracted output: bytes=%d digest=%x err=%v", storedBytes, storedDigest, err)
	}
	if err := workerRepo.Complete(ctx, job, outputKey, document, now.Add(time.Second)); err != nil {
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
	if indexerDSN := os.Getenv("KEEL_TEST_RETRIEVAL_INDEXER_DATABASE_URL"); indexerDSN != "" {
		indexerDB := openRoleDB(t, indexerDSN, "keel_local_retrieval_indexer", "keel-retrieval-indexer-local-only")
		visibility := "supplier-intake-reader:" + uuid.NewString()
		if err := tenancy.WithTenantTx(ctx, indexerDB, tenant, nil, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `SELECT set_config('keel.visibility_key',$1,true)`, visibility); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.retrieval_source_eligibility
				(tenant_id,visibility_key,document_version_id,state,generation) VALUES ($1,$2,$3,'active',1)`, string(tenant), visibility, uploadID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		documentID, err := uuid.Parse(uploadID)
		if err != nil {
			t.Fatal(err)
		}
		hasher, err := index.NewHMACTermHasher(string(tenant), "citation-test-v1", bytesOf(0x51, 32))
		if err != nil {
			t.Fatal(err)
		}
		text := string(document.Text)
		tokens, err := contracts.Tokenize(text)
		if err != nil {
			t.Fatal(err)
		}
		chunk, err := index.PrepareChunk(documentID, contracts.Chunk{Ordinal: 0, Text: text, StartByte: 0, EndByte: len(text), TokenCount: len(tokens)}, hasher)
		if err != nil {
			t.Fatal(err)
		}
		indexer, err := retrievalpg.New(indexerDB)
		if err != nil {
			t.Fatal(err)
		}
		buildID, manifest := uuid.New(), sha256.Sum256([]byte("supplier citation test manifest"))
		spec := index.BuildSpec{ID: buildID, AnalyzerID: "keel.word.v1", ChunkerID: contracts.ChunkerID,
			TermKeyID: hasher.KeyID(), ManifestDigest: manifest, ExpectedChunks: 1}
		if err := indexer.BeginBuild(ctx, tenant, visibility, spec); err != nil {
			t.Fatal(err)
		}
		if err := indexer.StageBatch(ctx, tenant, visibility, buildID, []index.Chunk{chunk}); err != nil {
			t.Fatal(err)
		}
		if _, err := indexer.Finalize(ctx, tenant, visibility, buildID); err != nil {
			t.Fatal(err)
		}
		if _, err := indexer.Publish(ctx, tenant, visibility, buildID, 0); err != nil {
			t.Fatal(err)
		}
		reader, err := citationintake.NewReader(appDB, objects)
		if err != nil {
			t.Fatal(err)
		}
		ref := hybrid.CitationRef{ChunkID: chunk.ID, DocumentVersionID: documentID, Ordinal: chunk.Ordinal,
			StartByte: chunk.StartByte, EndByte: chunk.EndByte, ContentDigest: chunk.ContentDigest}
		resolved, err := reader.ReadCitationRange(ctx, tenant, visibility, ref)
		if err != nil || string(resolved) != text {
			t.Fatalf("read authorized extracted citation: %q err=%v", resolved, err)
		}
		forged := ref
		forged.StartByte++
		if _, err := reader.ReadCitationRange(ctx, tenant, visibility, forged); !errors.Is(err, hybrid.ErrCitationNotAuthorized) {
			t.Fatalf("citation accepted an unindexed byte range: %v", err)
		}
		if _, err := reader.ReadCitationRange(ctx, tenant, "other:"+uuid.NewString(), ref); !errors.Is(err, hybrid.ErrCitationNotAuthorized) {
			t.Fatalf("citation was readable from a different cohort: %v", err)
		}
		appRetrieval, err := retrievalpg.New(appDB)
		if err != nil {
			t.Fatal(err)
		}
		withdrawal, err := appRetrieval.WithdrawSource(ctx, tenant, visibility, uuid.New(), documentID, uuid.New())
		if err != nil {
			t.Fatal(err)
		}
		receiptWriter := citationintake.SourceErasureReceiptWriterFunc(func(ctx context.Context, fence citationintake.ErasureFence, actor uuid.UUID, digest [32]byte) error {
			_, err := indexer.RecordErasureActionReceipt(ctx, fence.Tenant, fence.Visibility, fence.WorkerID,
				fence.JobID, fence.LeaseEpoch, retrievalpg.ErasureActionSupplierSourceObject,
				retrievalpg.ErasureReceiptComplete, actor, "", digest)
			return err
		})
		eraser, err := citationintake.NewEraser(appDB, objects, &testLegalHoldAuthority{}, receiptWriter)
		if err != nil {
			t.Fatal(err)
		}
		if err := eraser.EraseClaimed(ctx, tenant, visibility, "eraser-a", withdrawal.ID, 1); !errors.Is(err, citationintake.ErrSourceErasureNotAuthorized) {
			t.Fatalf("source erasure ran before a worker claimed its durable job: %v", err)
		}
		for _, key := range []string{objectKey, outputKey} {
			object, err := objects.Open(ctx, key)
			if err != nil {
				t.Fatalf("unclaimed erasure deleted source object %q: %v", key, err)
			}
			_ = object.Close()
		}
		claim, claimed, err := indexer.ClaimErasureJob(ctx, tenant, visibility, "eraser-a", time.Minute)
		if err != nil || !claimed || claim.ID != withdrawal.ID {
			t.Fatalf("claim source erasure job: claim=%+v claimed=%t err=%v", claim, claimed, err)
		}
		if err := eraser.EraseClaimed(ctx, tenant, visibility, "eraser-a", claim.ID, claim.LeaseEpoch); !errors.Is(err, citationintake.ErrSourceErasureNotAuthorized) {
			t.Fatalf("source erasure ran without a legal-hold clearance receipt: %v", err)
		}
		if _, err := indexer.RecordErasureActionReceipt(ctx, tenant, visibility, "eraser-a", claim.ID, claim.LeaseEpoch,
			retrievalpg.ErasureActionLegalHoldCheck, retrievalpg.ErasureReceiptComplete, uuid.New(), "", sha256.Sum256([]byte("synthetic legal-hold clearance fixture"))); err != nil {
			t.Fatalf("record synthetic legal-hold clearance fixture: %v", err)
		}
		if err := eraser.EraseClaimed(ctx, tenant, visibility, "eraser-a", claim.ID, claim.LeaseEpoch); !errors.Is(err, citationintake.ErrSourceErasureNotAuthorized) {
			t.Fatalf("source erasure proceeded while legal-hold authority denied clearance: %v", err)
		}
		for _, key := range []string{objectKey, outputKey} {
			object, err := objects.Open(ctx, key)
			if err != nil {
				t.Fatalf("hold denial deleted source object %q: %v", key, err)
			}
			_ = object.Close()
		}
		clearHold := &testLegalHoldAuthority{clear: true}
		eraser, err = citationintake.NewEraser(appDB, objects, clearHold, receiptWriter)
		if err != nil {
			t.Fatal(err)
		}
		if err := eraser.EraseClaimed(ctx, tenant, visibility, "eraser-b", claim.ID, claim.LeaseEpoch); !errors.Is(err, citationintake.ErrSourceErasureNotAuthorized) {
			t.Fatalf("source erasure accepted a different lease owner: %v", err)
		}
		if err := eraser.EraseClaimed(ctx, otherTenant, visibility, "eraser-a", claim.ID, claim.LeaseEpoch); !errors.Is(err, citationintake.ErrSourceErasureNotAuthorized) {
			t.Fatalf("source erasure crossed tenant scope: %v", err)
		}
		if err := eraser.EraseClaimed(ctx, tenant, visibility, "eraser-a", claim.ID, claim.LeaseEpoch+1); !errors.Is(err, citationintake.ErrSourceErasureNotAuthorized) {
			t.Fatalf("source erasure accepted a stale lease epoch: %v", err)
		}
		partial, err := citationintake.NewEraser(appDB, &failOnceObjectDeleter{store: objects, failKey: objectKey}, clearHold, receiptWriter)
		if err != nil {
			t.Fatal(err)
		}
		if err := partial.EraseClaimed(ctx, tenant, visibility, "eraser-a", claim.ID, claim.LeaseEpoch); err == nil {
			t.Fatal("injected raw object deletion failure was hidden")
		}
		if object, err := objects.Open(ctx, outputKey); err == nil {
			_ = object.Close()
			t.Fatal("partial erasure left the already-deleted extracted object present")
		}
		if object, err := objects.Open(ctx, objectKey); err != nil {
			t.Fatalf("partial erasure unexpectedly removed the raw object: %v", err)
		} else {
			_ = object.Close()
		}
		var sourceReceipts int
		if err := tenancy.WithTenantTx(ctx, indexerDB, tenant, nil, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `SELECT set_config('keel.visibility_key',$1,true)`, visibility); err != nil {
				return err
			}
			return tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.retrieval_erasure_action_receipts
				WHERE tenant_id=$1 AND visibility_key=$2 AND job_id=$3 AND action_key=$4`, string(tenant), visibility, claim.ID,
				retrievalpg.ErasureActionSupplierSourceObject).Scan(&sourceReceipts)
		}); err != nil || sourceReceipts != 0 {
			t.Fatalf("partial deletion was acknowledged by a receipt: count=%d err=%v", sourceReceipts, err)
		}
		if err := eraser.EraseClaimed(ctx, tenant, visibility, "eraser-a", claim.ID, claim.LeaseEpoch); err != nil {
			t.Fatalf("erase withdrawn supplier source objects: %v", err)
		}
		if !clearHold.released {
			t.Fatal("legal-hold clearance was not released after the destructive action")
		}
		retry, err := citationintake.NewEraser(appDB, objects, &testLegalHoldAuthority{}, receiptWriter)
		if err != nil {
			t.Fatal(err)
		}
		if err := retry.EraseClaimed(ctx, tenant, visibility, "eraser-a", claim.ID, claim.LeaseEpoch); err != nil {
			t.Fatalf("retry idempotent source object erasure: %v", err)
		}
		for _, key := range []string{objectKey, outputKey} {
			if object, err := objects.Open(ctx, key); err == nil {
				_ = object.Close()
				t.Fatalf("source object %q remained after erasure", key)
			}
		}
		if _, err := reader.ReadCitationRange(ctx, tenant, visibility, ref); !errors.Is(err, hybrid.ErrCitationNotAuthorized) {
			t.Fatalf("withdrawn citation remained readable: %v", err)
		}
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
