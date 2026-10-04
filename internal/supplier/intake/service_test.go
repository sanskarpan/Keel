package intake

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const serviceTenant = "11111111-1111-4111-8111-111111111111"
const serviceUpload = "22222222-2222-4222-8222-222222222222"

func TestServiceVerifiesBeforeQuarantineAndProcessesBeforePublishing(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	data := []byte("synthetic supplier evidence")
	checksum := sha256.Sum256(data)
	metadata := UploadMetadata{Filename: "supplier.txt", ContentType: string(FormatText), Size: int64(len(data)), SHA256: hex.EncodeToString(checksum[:])}
	key := bytes.Repeat([]byte{0x73}, 32)
	capability, err := SignUploadCapability(UploadCapability{
		TenantID: serviceTenant, InviteID: "33333333-3333-4333-8333-333333333333", UploadID: serviceUpload,
		Size: metadata.Size, SHA256: metadata.SHA256, ExpiresAt: now.Add(5 * time.Minute), Purpose: "supplier-upload-v1",
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	repository := &fakeRepository{job: UploadJob{
		TenantID: mustServiceTenant(t), UploadID: serviceUpload, InvitationID: "33333333-3333-4333-8333-333333333333", ObjectKey: serviceUpload,
		Metadata:   UploadMetadata{Filename: "evidence.txt", ContentType: metadata.ContentType, Size: metadata.Size, SHA256: metadata.SHA256},
		ClaimOwner: "processor-1", ClaimEpoch: 1, Attempt: 1,
	}, metadata: UploadMetadata{Filename: "evidence.txt", ContentType: metadata.ContentType, Size: metadata.Size, SHA256: metadata.SHA256}, inviteID: "33333333-3333-4333-8333-333333333333", capabilityExpires: now.Add(5 * time.Minute)}
	store, err := NewLocalStore(filepath.Join(t.TempDir(), "objects"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service, err := NewService(repository, store, key, scannerFunc(func(context.Context, io.Reader) error { return nil }), extractorFunc(func(context.Context, Format, io.Reader, int64) ([]byte, error) {
		return []byte("normalized evidence"), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	tenant := mustServiceTenant(t)
	if err := service.Receive(ctx, tenant, serviceUpload, "wrong-token", bytes.NewReader(data), now); !errors.Is(err, ErrInvalidCapability) {
		t.Fatalf("wrong capability error=%v", err)
	}
	if err := service.Receive(ctx, tenant, serviceUpload, capability, bytes.NewReader([]byte("modified")), now); !errors.Is(err, ErrInvalidUpload) {
		t.Fatalf("modified upload error=%v", err)
	}
	if _, err := store.Open(ctx, serviceUpload); err == nil {
		t.Fatal("invalid upload was written to quarantine")
	}
	if err := service.Receive(ctx, tenant, serviceUpload, capability, bytes.NewReader(data), now); err != nil {
		t.Fatal(err)
	}
	if repository.markedBytes != metadata.Size || repository.markedFormat != FormatText {
		t.Fatalf("uploaded row was not finalized with verified metadata: %+v", repository)
	}
	found, err := service.ProcessNext(ctx, tenant, "processor-1", now, time.Minute)
	if err != nil || !found {
		t.Fatalf("process next found=%v err=%v", found, err)
	}
	if repository.completed == nil || string(repository.completed.Text) != "normalized evidence" || repository.completedKey == "" || repository.failedCode != "" {
		t.Fatalf("clean document was not published after processing: %+v", repository)
	}
	published, err := store.Open(ctx, repository.completedKey)
	if err != nil {
		t.Fatal(err)
	}
	result, err := io.ReadAll(published)
	_ = published.Close()
	if err != nil || string(result) != "normalized evidence" {
		t.Fatalf("published result=%q err=%v", result, err)
	}
}

func TestServiceScannerFailureIsRetryableAndNeverPublishesText(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	data := []byte("safe-looking input")
	digest := sha256.Sum256(data)
	repository := &fakeRepository{job: UploadJob{
		TenantID: mustServiceTenant(t), UploadID: serviceUpload, ObjectKey: serviceUpload,
		Metadata:   UploadMetadata{Filename: "evidence.txt", ContentType: string(FormatText), Size: int64(len(data)), SHA256: hex.EncodeToString(digest[:])},
		ClaimOwner: "processor-1", ClaimEpoch: 1, Attempt: 1,
	}}
	store, err := NewLocalStore(filepath.Join(t.TempDir(), "objects"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, _, err := store.Put(ctx, serviceUpload, bytes.NewReader(data), MaxUploadBytes); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(repository, store, bytes.Repeat([]byte{0x11}, 32), scannerFunc(func(context.Context, io.Reader) error { return errors.New("daemon detail") }), extractorFunc(func(context.Context, Format, io.Reader, int64) ([]byte, error) {
		t.Fatal("extractor ran after scanner outage")
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	found, err := service.ProcessNext(ctx, mustServiceTenant(t), "processor-1", now, time.Minute)
	if err != nil || !found || repository.failedCode != "scanner_unavailable" || repository.completed != nil || !repository.failedRetryable {
		t.Fatalf("scanner failure state found=%v err=%v repository=%+v", found, err, repository)
	}
}

type fakeRepository struct {
	job               UploadJob
	metadata          UploadMetadata
	inviteID          string
	capabilityExpires time.Time
	markedBytes       int64
	markedFormat      Format
	completeKey       string
	completed         *ProcessedDocument
	completedKey      string
	failedCode        string
	failedRetryable   bool
	markErr           error
}

func (r *fakeRepository) LoadUploadMetadata(context.Context, tenancy.TenantID, string, time.Time) (string, UploadMetadata, time.Time, error) {
	if r.metadata.Filename == "" {
		return "", UploadMetadata{}, time.Time{}, errors.New("not found")
	}
	return r.inviteID, r.metadata, r.capabilityExpires, nil
}

func (r *fakeRepository) MarkUploaded(_ context.Context, _ tenancy.TenantID, _ string, _ string, size int64, _ string, format Format, _ time.Time) error {
	if r.markErr != nil {
		return r.markErr
	}
	r.markedBytes, r.markedFormat = size, format
	return nil
}
func (r *fakeRepository) ClaimNext(context.Context, tenancy.TenantID, string, time.Time, time.Duration) (UploadJob, error) {
	if r.job.UploadID == "" {
		return UploadJob{}, ErrNoJob
	}
	return r.job, nil
}
func (r *fakeRepository) Complete(_ context.Context, _ UploadJob, key string, document ProcessedDocument, _ time.Time) error {
	copy := document
	copy.Text = append([]byte(nil), document.Text...)
	r.completed, r.completedKey, r.completeKey = &copy, key, key
	return nil
}
func (r *fakeRepository) Fail(_ context.Context, _ UploadJob, code string, permanent bool, _ time.Time) error {
	r.failedCode, r.failedRetryable = code, !permanent
	return nil
}
func mustServiceTenant(t *testing.T) tenancy.TenantID {
	t.Helper()
	tenant, err := tenancy.ParseTenantID(serviceTenant)
	if err != nil {
		t.Fatal(err)
	}
	return tenant
}
