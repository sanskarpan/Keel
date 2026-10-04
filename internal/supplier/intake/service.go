package intake

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

type IntakeRepository interface {
	LoadUploadMetadata(context.Context, tenancy.TenantID, string, time.Time) (string, UploadMetadata, time.Time, error)
	MarkUploaded(context.Context, tenancy.TenantID, string, string, int64, string, Format, time.Time) error
	ClaimNext(context.Context, tenancy.TenantID, string, time.Time, time.Duration) (UploadJob, error)
	Complete(context.Context, UploadJob, string, ProcessedDocument, time.Time) error
	Fail(context.Context, UploadJob, string, bool, time.Time) error
}

// Service coordinates capability verification, quarantine persistence, database state, and
// the fail-closed scan/extract worker. It never makes extracted text available before Complete.
type Service struct {
	repository    IntakeRepository
	objects       BlobStore
	capabilityKey []byte
	scanner       Scanner
	extractor     Extractor
}

func NewService(repository IntakeRepository, objects BlobStore, capabilityKey []byte, scanner Scanner, extractor Extractor) (*Service, error) {
	if repository == nil || objects == nil || len(capabilityKey) < 32 || scanner == nil || extractor == nil {
		return nil, errors.New("supplier intake dependencies are incomplete")
	}
	return &Service{
		repository:    repository,
		objects:       objects,
		capabilityKey: append([]byte(nil), capabilityKey...),
		scanner:       scanner,
		extractor:     extractor,
	}, nil
}

// Receive verifies the short-lived upload capability and actual bytes before writing the
// quarantine object and transitioning the DB row to queued. Callers expose this only behind a
// dedicated upload route with strict deadlines and authenticated tenant context.
func (s *Service) Receive(ctx context.Context, tenant tenancy.TenantID, uploadID, capability string, source io.Reader, now time.Time) error {
	if s == nil || ctx == nil || source == nil {
		return errors.New("supplier upload request is incomplete")
	}
	invitationID, metadata, capabilityExpires, err := s.repository.LoadUploadMetadata(ctx, tenant, uploadID, now)
	if err != nil {
		return ErrInvalidCapability
	}
	claims, err := VerifyUploadCapability(capability, s.capabilityKey, now, string(tenant), uploadID, metadata)
	if err != nil {
		return ErrInvalidCapability
	}
	if claims.InviteID != invitationID || !claims.ExpiresAt.Equal(capabilityExpires) {
		return ErrInvalidCapability
	}
	data, format, err := VerifyObject(metadata, source)
	if err != nil {
		return err
	}
	count, digest, err := s.objects.Put(ctx, uploadID, bytes.NewReader(data), MaxUploadBytes)
	if err != nil {
		return errors.New("supplier upload could not be quarantined")
	}
	if count != int64(len(data)) || digest != sha256.Sum256(data) {
		_ = s.objects.Delete(ctx, uploadID)
		return errors.New("quarantine store returned an inconsistent object receipt")
	}
	if err := s.repository.MarkUploaded(ctx, tenant, uploadID, claims.InviteID, count, metadata.SHA256, format, now); err != nil {
		_ = s.objects.Delete(ctx, uploadID)
		return errors.New("supplier upload could not be finalized")
	}
	return nil
}

// ProcessNext claims one tenant-scoped job. Expected content/scanner failures are recorded on
// the row; infrastructure failures are retryable and never publish extracted output.
func (s *Service) ProcessNext(ctx context.Context, tenant tenancy.TenantID, owner string, now time.Time, lease time.Duration) (bool, error) {
	if s == nil || ctx == nil {
		return false, errors.New("supplier processor request is incomplete")
	}
	job, err := s.repository.ClaimNext(ctx, tenant, owner, now, lease)
	if errors.Is(err, ErrNoJob) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("supplier upload job could not be claimed")
	}
	if job.Metadata.Filename == "" || job.ObjectKey != job.UploadID {
		if err := s.repository.Fail(ctx, job, "unsupported_content", true, now); err != nil {
			return true, errors.New("invalid supplier job could not be recorded")
		}
		return true, nil
	}
	object, err := s.objects.Open(ctx, job.ObjectKey)
	if err != nil {
		if failErr := s.repository.Fail(ctx, job, "scanner_unavailable", false, now); failErr != nil {
			return true, errors.New("missing quarantine object could not be recorded")
		}
		return true, nil
	}
	document, processErr := Process(ctx, job.Metadata, object, s.scanner, s.extractor)
	closeErr := object.Close()
	if processErr == nil && closeErr != nil {
		processErr = closeErr
	}
	if processErr != nil {
		code, permanent := failureCode(processErr)
		if err := s.repository.Fail(ctx, job, code, permanent, now); err != nil {
			return true, errors.New("supplier processing failure could not be recorded")
		}
		return true, nil
	}
	outputKey, err := NewObjectID(nil)
	if err != nil {
		_ = s.repository.Fail(ctx, job, "extraction_failed", false, now)
		return true, errors.New("supplier extraction output could not be allocated")
	}
	outputSize, outputDigest, err := s.objects.Put(ctx, outputKey, bytes.NewReader(document.Text), MaxExtractedSize)
	if err != nil {
		if failErr := s.repository.Fail(ctx, job, "extraction_failed", false, now); failErr != nil {
			return true, errors.New("supplier extraction failure could not be recorded")
		}
		return true, nil
	}
	if outputSize != int64(len(document.Text)) || outputDigest != document.TextSHA256 {
		_ = s.objects.Delete(ctx, outputKey)
		if failErr := s.repository.Fail(ctx, job, "extraction_failed", false, now); failErr != nil {
			return true, errors.New("inconsistent extraction output could not be recorded")
		}
		return true, nil
	}
	if err := s.repository.Complete(ctx, job, outputKey, document, now); err != nil {
		_ = s.objects.Delete(ctx, outputKey)
		return true, errors.New("supplier extraction result could not be committed")
	}
	return true, nil
}

func failureCode(err error) (string, bool) {
	switch {
	case errors.Is(err, ErrMalwareFound):
		return "malware_detected", true
	case errors.Is(err, ErrScannerUnavailable):
		return "scanner_unavailable", false
	case errors.Is(err, ErrOutputLimit):
		return "output_limit", true
	case errors.Is(err, ErrExtractionFailed):
		return "extraction_failed", false
	default:
		return "unsupported_content", true
	}
}
