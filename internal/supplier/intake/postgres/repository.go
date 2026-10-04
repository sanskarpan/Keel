// Package postgres stores supplier invitations and quarantined upload state.
package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/supplier/intake"
)

const (
	maxInvitationTTL = 7 * 24 * time.Hour
	maxSessionTTL    = 24 * time.Hour
	maxUploads       = 5
	maxJobAttempts   = 5
)

var (
	ErrNotFound      = errors.New("supplier invitation or upload not found")
	ErrConflict      = errors.New("supplier invitation or upload state conflict")
	ErrInvalidRecord = errors.New("supplier invitation or upload record is invalid")
	principalPattern = regexp.MustCompile(`^(principal|service-principal):[A-Za-z0-9._~-]{1,120}$`)
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) (*Repository, error) {
	if db == nil {
		return nil, errors.New("supplier intake database is required")
	}
	return &Repository{db: db}, nil
}

type Invitation struct {
	TenantID     tenancy.TenantID
	InvitationID string
	CaseID       string
	SupplierID   string
	State        string
	ExpiresAt    time.Time
}

type Upload struct {
	TenantID     tenancy.TenantID
	UploadID     string
	InvitationID string
	ObjectKey    string
	Metadata     intake.UploadMetadata
	State        string
}

type UploadStatus struct {
	State     string
	UpdatedAt time.Time
}

func (r *Repository) LoadUploadMetadata(ctx context.Context, tenant tenancy.TenantID, uploadID string, now time.Time) (string, intake.UploadMetadata, time.Time, error) {
	if r == nil || r.db == nil || !validID(uploadID) {
		return "", intake.UploadMetadata{}, time.Time{}, ErrInvalidRecord
	}
	var invitationID, contentType string
	var size int64
	var checksum []byte
	var expires time.Time
	err := tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		query := `SELECT u.invitation_id::text,u.declared_media_type,u.expected_bytes,u.expected_sha256,u.upload_expires_at
			FROM keel_meta.supplier_uploads u
			JOIN keel_meta.supplier_upload_sessions s ON s.tenant_id=u.tenant_id AND s.session_id=u.session_id
			JOIN keel_meta.supplier_invitations i ON i.tenant_id=u.tenant_id AND i.invitation_id=u.invitation_id
			WHERE u.tenant_id=$1 AND u.upload_id=$2 AND u.upload_state='awaiting_upload' AND u.upload_expires_at>$3
			  AND s.expires_at>$3 AND s.revoked_at IS NULL
			  AND i.invitation_state='accepted' AND i.expires_at>$3 AND i.revoked_at IS NULL`
		if err := tx.QueryRowContext(ctx, query, string(tenant), uploadID, now.UTC()).Scan(&invitationID, &contentType, &size, &checksum, &expires); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("supplier upload metadata query failed: %w", err)
		}
		return nil
	})
	if err != nil {
		return "", intake.UploadMetadata{}, time.Time{}, err
	}
	filename := "evidence"
	switch contentType {
	case string(intake.FormatPDF):
		filename += ".pdf"
	case string(intake.FormatDOCX):
		filename += ".docx"
	case string(intake.FormatText):
		filename += ".txt"
	default:
		return "", intake.UploadMetadata{}, time.Time{}, ErrInvalidRecord
	}
	return invitationID, intake.UploadMetadata{Filename: filename, ContentType: contentType, Size: size, SHA256: hex.EncodeToString(checksum)}, expires, nil
}

func (r *Repository) RenewCapability(ctx context.Context, tenant tenancy.TenantID, sessionToken, uploadID string, now, expires time.Time, key []byte) (string, error) {
	if r == nil || r.db == nil || !validID(uploadID) || expires.Before(now.Add(time.Second)) || expires.After(now.Add(intake.MaxUploadCapabilityTTL)) {
		return "", ErrInvalidRecord
	}
	expires = expires.UTC().Truncate(time.Second)
	if !expires.After(now.UTC()) || len(key) < 32 {
		return "", ErrInvalidRecord
	}
	sessionDigest, err := intake.TokenDigest(sessionToken, "supplier-upload-session-v1")
	if err != nil {
		return "", ErrNotFound
	}
	var invitationID, mediaType string
	var size int64
	var checksum []byte
	var capability string
	err = tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		query := `SELECT u.invitation_id::text,u.declared_media_type,u.expected_bytes,u.expected_sha256
			FROM keel_meta.supplier_uploads u
			JOIN keel_meta.supplier_upload_sessions s ON s.tenant_id=u.tenant_id AND s.session_id=u.session_id
			JOIN keel_meta.supplier_invitations i ON i.tenant_id=u.tenant_id AND i.invitation_id=u.invitation_id
			WHERE u.tenant_id=$1 AND u.upload_id=$2 AND u.upload_state='awaiting_upload'
			  AND s.session_token_digest=$3 AND s.expires_at>$4 AND s.revoked_at IS NULL
			  AND i.invitation_state='accepted' AND i.expires_at>$4 AND i.revoked_at IS NULL
			FOR UPDATE OF i`
		if err := tx.QueryRowContext(ctx, query, string(tenant), uploadID, sessionDigest[:], now.UTC()).Scan(&invitationID, &mediaType, &size, &checksum); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return errors.New("supplier upload capability could not be renewed")
		}
		metadata := intake.UploadMetadata{Filename: serverFilename(mediaType), ContentType: mediaType, Size: size, SHA256: hex.EncodeToString(checksum)}
		capability, err = intake.SignUploadCapability(intake.UploadCapability{
			TenantID: string(tenant), InviteID: invitationID, UploadID: uploadID,
			Size: size, SHA256: metadata.SHA256, ExpiresAt: expires, Purpose: "supplier-upload-v1",
		}, key)
		if err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `UPDATE keel_meta.supplier_uploads SET upload_expires_at=$1,updated_at=$2
			WHERE tenant_id=$3 AND upload_id=$4 AND upload_state='awaiting_upload'`, expires, now.UTC(), string(tenant), uploadID)
		if err != nil {
			return errors.New("supplier upload capability could not be renewed")
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return capability, nil
}

func serverFilename(mediaType string) string {
	switch mediaType {
	case string(intake.FormatPDF):
		return "evidence.pdf"
	case string(intake.FormatDOCX):
		return "evidence.docx"
	case string(intake.FormatText):
		return "evidence.txt"
	default:
		return ""
	}
}

func (r *Repository) GetUploadStatus(ctx context.Context, tenant tenancy.TenantID, sessionToken, uploadID string, now time.Time) (UploadStatus, error) {
	if r == nil || r.db == nil || !validID(uploadID) {
		return UploadStatus{}, ErrInvalidRecord
	}
	digest, err := intake.TokenDigest(sessionToken, "supplier-upload-session-v1")
	if err != nil {
		return UploadStatus{}, ErrNotFound
	}
	var status UploadStatus
	err = tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		query := `SELECT u.upload_state,u.updated_at
			FROM keel_meta.supplier_uploads u
			JOIN keel_meta.supplier_upload_sessions s ON s.tenant_id=u.tenant_id AND s.session_id=u.session_id
			JOIN keel_meta.supplier_invitations i ON i.tenant_id=u.tenant_id AND i.invitation_id=u.invitation_id
			WHERE u.tenant_id=$1 AND u.upload_id=$2 AND s.session_token_digest=$3
			  AND s.expires_at>$4 AND s.revoked_at IS NULL
			  AND i.invitation_state='accepted' AND i.expires_at>$4 AND i.revoked_at IS NULL`
		if err := tx.QueryRowContext(ctx, query, string(tenant), uploadID, digest[:], now.UTC()).Scan(&status.State, &status.UpdatedAt); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return errors.New("supplier upload status could not be loaded")
		}
		return nil
	})
	if err != nil {
		return UploadStatus{}, err
	}
	return status, nil
}

type UploadJob = intake.UploadJob

// RecipientDigest uses a dedicated pepper so a database snapshot cannot dictionary-attack
// supplier addresses. The raw address is never stored in this service's schema.
func RecipientDigest(address string, pepper []byte) ([sha256.Size]byte, error) {
	parsed, err := mail.ParseAddress(strings.TrimSpace(address))
	if err != nil || parsed.Name != "" || parsed.Address == "" || !isASCII(parsed.Address) || len(pepper) < 32 {
		return [sha256.Size]byte{}, errors.New("recipient address or digest pepper is invalid")
	}
	normalized := strings.ToLower(strings.TrimSpace(parsed.Address))
	mac := hmac.New(sha256.New, pepper)
	_, _ = mac.Write([]byte("keel:supplier-recipient:v1\x00" + normalized))
	var digest [sha256.Size]byte
	copy(digest[:], mac.Sum(nil))
	return digest, nil
}

func isASCII(value string) bool {
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func (r *Repository) IssueInvitation(ctx context.Context, tenant tenancy.TenantID, invitationID, caseID, supplierID, rawToken string, recipientDigest [sha256.Size]byte, issuerRef string, now, expires time.Time) error {
	if r == nil || r.db == nil || !validID(invitationID) || !validID(caseID) || !validID(supplierID) || !principalPattern.MatchString(issuerRef) || expires.Before(now.Add(time.Minute)) || expires.After(now.Add(maxInvitationTTL)) || recipientDigest == [sha256.Size]byte{} {
		return ErrInvalidRecord
	}
	tokenDigest, err := intake.TokenDigest(rawToken, "supplier-invitation-v1")
	if err != nil {
		return ErrInvalidRecord
	}
	return tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.supplier_invitations
			(tenant_id, invitation_id, case_id, supplier_id, recipient_digest, invitation_token_digest, invitation_state, issued_by_ref, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,'pending',$7,$8)`, string(tenant), invitationID, caseID, supplierID, recipientDigest[:], tokenDigest[:], issuerRef, expires.UTC())
		if err != nil {
			return errors.New("supplier invitation could not be created")
		}
		return nil
	})
}

// AcceptInvitation consumes the single-purpose supplier invitation and returns a new
// short-lived upload-session bearer once. Only purpose-separated token digests are persisted.
func (r *Repository) AcceptInvitation(ctx context.Context, tenant tenancy.TenantID, rawToken, sessionID string, now time.Time, source io.Reader) (Invitation, string, error) {
	if r == nil || r.db == nil || !validID(sessionID) {
		return Invitation{}, "", intake.ErrInvalidInvitation
	}
	inviteDigest, err := intake.TokenDigest(rawToken, "supplier-invitation-v1")
	if err != nil {
		return Invitation{}, "", intake.ErrInvalidInvitation
	}
	sessionToken, err := intake.NewSecret(source)
	if err != nil {
		return Invitation{}, "", errors.New("supplier session could not be created")
	}
	sessionDigest, err := intake.TokenDigest(sessionToken, "supplier-upload-session-v1")
	if err != nil {
		return Invitation{}, "", errors.New("supplier session could not be created")
	}
	var invitation Invitation
	var operationErr error
	err = tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		var acceptedAt time.Time
		query := `UPDATE keel_meta.supplier_invitations
			SET invitation_state='accepted', accepted_at=$1, updated_at=$1
			WHERE tenant_id=$2 AND invitation_token_digest=$3 AND invitation_state='pending' AND expires_at>$1
			RETURNING invitation_id::text,case_id::text,supplier_id::text,expires_at`
		if err := tx.QueryRowContext(ctx, query, now.UTC(), string(tenant), inviteDigest[:]).Scan(&invitation.InvitationID, &invitation.CaseID, &invitation.SupplierID, &invitation.ExpiresAt); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				operationErr = intake.ErrInvalidInvitation
				return nil
			}
			return errors.New("supplier invitation could not be accepted")
		}
		acceptedAt = now.UTC()
		invitation.TenantID, invitation.State = tenant, "accepted"
		sessionExpiry := acceptedAt.Add(maxSessionTTL)
		if invitation.ExpiresAt.Before(sessionExpiry) {
			sessionExpiry = invitation.ExpiresAt
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.supplier_upload_sessions
			(tenant_id,session_id,invitation_id,session_token_digest,expires_at)
			VALUES ($1,$2,$3,$4,$5)`, string(tenant), sessionID, invitation.InvitationID, sessionDigest[:], sessionExpiry)
		if err != nil {
			return errors.New("supplier session could not be created")
		}
		return nil
	})
	if err != nil {
		return Invitation{}, "", err
	}
	if operationErr != nil {
		return Invitation{}, "", operationErr
	}
	return invitation, sessionToken, nil
}

func (r *Repository) CreateUpload(ctx context.Context, tenant tenancy.TenantID, sessionToken, uploadID, objectKey string, metadata intake.UploadMetadata, now, expires time.Time, capabilityKey []byte) (Upload, string, error) {
	if r == nil || r.db == nil || !validID(uploadID) || objectKey != uploadID || intake.ValidateUploadMetadata(metadata) != nil || expires.Before(now.Add(time.Second)) || expires.After(now.Add(intake.MaxUploadCapabilityTTL)) {
		return Upload{}, "", ErrInvalidRecord
	}
	expires = expires.UTC().Truncate(time.Second)
	if !expires.After(now.UTC()) {
		return Upload{}, "", ErrInvalidRecord
	}
	sessionDigest, err := intake.TokenDigest(sessionToken, "supplier-upload-session-v1")
	if err != nil {
		return Upload{}, "", ErrNotFound
	}
	var upload Upload
	var capability string
	err = tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		var sessionID, invitationID string
		query := `SELECT s.session_id::text,s.invitation_id::text
			FROM keel_meta.supplier_upload_sessions s
			JOIN keel_meta.supplier_invitations i USING (tenant_id,invitation_id)
			WHERE s.tenant_id=$1 AND s.session_token_digest=$2 AND s.expires_at>$3 AND s.revoked_at IS NULL
			  AND i.invitation_state='accepted' AND i.expires_at>$3 AND i.revoked_at IS NULL
			FOR UPDATE OF i`
		if err := tx.QueryRowContext(ctx, query, string(tenant), sessionDigest[:], now.UTC()).Scan(&sessionID, &invitationID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return errors.New("supplier upload session could not be validated")
		}
		var existing int
		if _, err := tx.ExecContext(ctx, `UPDATE keel_meta.supplier_uploads
			SET upload_state='expired',updated_at=$1
			WHERE tenant_id=$2 AND invitation_id=$3 AND upload_state='awaiting_upload' AND upload_expires_at<=$1`, now.UTC(), string(tenant), invitationID); err != nil {
			return errors.New("expired supplier uploads could not be reconciled")
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.supplier_uploads WHERE tenant_id=$1 AND invitation_id=$2 AND upload_state<>'expired'`, string(tenant), invitationID).Scan(&existing); err != nil {
			return errors.New("supplier upload quota could not be checked")
		}
		if existing >= maxUploads {
			return ErrConflict
		}
		checksum, _ := hex.DecodeString(metadata.SHA256)
		_, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.supplier_uploads
			(tenant_id,upload_id,invitation_id,session_id,object_key,declared_media_type,expected_bytes,expected_sha256,upload_expires_at,upload_state)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'awaiting_upload')`, string(tenant), uploadID, invitationID, sessionID, objectKey, metadata.ContentType, metadata.Size, checksum, expires.UTC())
		if err != nil {
			return fmt.Errorf("supplier upload insert failed: %w", err)
		}
		capability, err = intake.SignUploadCapability(intake.UploadCapability{
			TenantID: string(tenant), InviteID: invitationID, UploadID: uploadID,
			Size: metadata.Size, SHA256: metadata.SHA256, ExpiresAt: expires.UTC(), Purpose: "supplier-upload-v1",
		}, capabilityKey)
		if err != nil {
			return err
		}
		upload = Upload{TenantID: tenant, UploadID: uploadID, InvitationID: invitationID, ObjectKey: objectKey, Metadata: metadata, State: "awaiting_upload"}
		return nil
	})
	if err != nil {
		return Upload{}, "", err
	}
	return upload, capability, nil
}

func (r *Repository) MarkUploaded(ctx context.Context, tenant tenancy.TenantID, uploadID, invitationID string, actualBytes int64, actualSHA256 string, detected intake.Format, now time.Time) error {
	if r == nil || r.db == nil || !validID(uploadID) || !validID(invitationID) || actualBytes < 1 || actualBytes > intake.MaxUploadBytes || len(actualSHA256) != 64 || strings.ToLower(actualSHA256) != actualSHA256 || !intakeFormat(detected) {
		return ErrInvalidRecord
	}
	digest, err := hex.DecodeString(actualSHA256)
	if err != nil {
		return ErrInvalidRecord
	}
	return tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE keel_meta.supplier_uploads u
			SET upload_state='queued',uploaded_at=$1,detected_media_type=$2,updated_at=$1
			FROM keel_meta.supplier_upload_sessions s,keel_meta.supplier_invitations i
			WHERE u.tenant_id=$3 AND u.upload_id=$4 AND u.invitation_id=$5 AND u.upload_state='awaiting_upload' AND u.upload_expires_at>$1
			  AND u.expected_bytes=$6 AND u.expected_sha256=$7 AND u.declared_media_type=$2
			  AND s.tenant_id=u.tenant_id AND s.session_id=u.session_id AND s.expires_at>$1 AND s.revoked_at IS NULL
			  AND i.tenant_id=u.tenant_id AND i.invitation_id=u.invitation_id AND i.invitation_state='accepted' AND i.expires_at>$1 AND i.revoked_at IS NULL`,
			now.UTC(), string(detected), string(tenant), uploadID, invitationID, actualBytes, digest)
		if err != nil {
			return errors.New("supplier upload could not be finalized")
		}
		count, err := result.RowsAffected()
		if err != nil {
			return errors.New("supplier upload could not be finalized")
		}
		if count != 1 {
			return ErrConflict
		}
		return nil
	})
}

func (r *Repository) ClaimNext(ctx context.Context, tenant tenancy.TenantID, owner string, now time.Time, lease time.Duration) (UploadJob, error) {
	if r == nil || r.db == nil || owner == "" || len(owner) > 120 || lease < 5*time.Second || lease > 5*time.Minute {
		return UploadJob{}, ErrInvalidRecord
	}
	var job UploadJob
	var found bool
	err := tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE keel_meta.supplier_uploads
			SET upload_state='rejected',last_error_code='scanner_unavailable',processed_at=$1,claim_owner=NULL,lease_until=NULL,updated_at=$1
			WHERE tenant_id=$2 AND attempt_count >= $3 AND (
				upload_state IN ('queued','retryable') OR (upload_state='scanning' AND lease_until <= $1)
			)`, now.UTC(), string(tenant), maxJobAttempts)
		if err != nil {
			return errors.New("supplier upload retry state could not be reconciled")
		}
		query := `SELECT upload_id::text,invitation_id::text,object_key::text,
			declared_media_type,expected_bytes,expected_sha256,claim_epoch,attempt_count
			FROM keel_meta.supplier_uploads
			WHERE tenant_id=$1 AND attempt_count < $2 AND (
				upload_state IN ('queued','retryable') OR (upload_state='scanning' AND lease_until <= $3)
			)
			ORDER BY created_at,upload_id
			FOR UPDATE SKIP LOCKED LIMIT 1`
		var checksum []byte
		var epoch int64
		var attempt int
		err = tx.QueryRowContext(ctx, query, string(tenant), maxJobAttempts, now.UTC()).Scan(&job.UploadID, &job.InvitationID, &job.ObjectKey, &job.Metadata.ContentType, &job.Metadata.Size, &checksum, &epoch, &attempt)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return errors.New("supplier upload queue could not be claimed")
		}
		result, err := tx.ExecContext(ctx, `UPDATE keel_meta.supplier_uploads
			SET upload_state='scanning',claim_owner=$1,claim_epoch=claim_epoch+1,lease_until=$2,
				attempt_count=attempt_count+1,last_error_code=NULL,processed_at=NULL,updated_at=$3
			WHERE tenant_id=$4 AND upload_id=$5 AND claim_epoch=$6`, owner, now.Add(lease).UTC(), now.UTC(), string(tenant), job.UploadID, epoch)
		if err != nil {
			return errors.New("supplier upload lease could not be acquired")
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			return ErrConflict
		}
		job.TenantID, job.ClaimOwner, job.ClaimEpoch, job.Attempt, job.LeaseUntil = tenant, owner, epoch+1, attempt+1, now.Add(lease).UTC()
		job.Metadata.SHA256 = hex.EncodeToString(checksum)
		// Never persist supplier-controlled filenames. Give the extractor a stable, safe,
		// content-derived name after the initial upload boundary has discarded that claim.
		switch job.Metadata.ContentType {
		case string(intake.FormatPDF):
			job.Metadata.Filename = "evidence.pdf"
		case string(intake.FormatDOCX):
			job.Metadata.Filename = "evidence.docx"
		case string(intake.FormatText):
			job.Metadata.Filename = "evidence.txt"
		default:
			return ErrInvalidRecord
		}
		found = true
		return nil
	})
	if err != nil {
		return UploadJob{}, err
	}
	if !found {
		return UploadJob{}, intake.ErrNoJob
	}
	return job, nil
}

func (r *Repository) Complete(ctx context.Context, job UploadJob, outputKey string, document intake.ProcessedDocument, now time.Time) error {
	if r == nil || r.db == nil || !validID(outputKey) || !validID(job.UploadID) || job.ClaimOwner == "" || job.ClaimEpoch < 1 || int64(len(document.Text)) > intake.MaxExtractedSize || document.Format != intake.Format(job.Metadata.ContentType) {
		return ErrInvalidRecord
	}
	if hex.EncodeToString(document.SourceSHA256[:]) != job.Metadata.SHA256 || sha256.Sum256(document.Text) != document.TextSHA256 {
		return ErrInvalidRecord
	}
	return tenancy.WithTenantTx(ctx, r.db, job.TenantID, nil, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE keel_meta.supplier_uploads
			SET upload_state='extracted',detected_media_type=$1,scanner_version=$2,scanned_at=$3,
				extracted_object_key=$4,extracted_bytes=$5,extracted_sha256=$6,processed_at=$3,
				claim_owner=NULL,lease_until=NULL,last_error_code=NULL,updated_at=$3
			WHERE tenant_id=$7 AND upload_id=$8 AND upload_state='scanning'
			  AND claim_owner=$9 AND claim_epoch=$10 AND lease_until>$3 AND expected_sha256=$11`,
			string(document.Format), "clamav+tika-v1", now.UTC(), outputKey, len(document.Text), document.TextSHA256[:], string(job.TenantID), job.UploadID, job.ClaimOwner, job.ClaimEpoch, document.SourceSHA256[:])
		if err != nil {
			return errors.New("processed supplier upload could not be recorded")
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			return ErrConflict
		}
		return nil
	})
}

func (r *Repository) Fail(ctx context.Context, job UploadJob, code string, permanent bool, now time.Time) error {
	allowed := map[string]bool{"malware_detected": true, "unsupported_content": true, "scanner_unavailable": true, "extraction_failed": true, "output_limit": true}
	if r == nil || r.db == nil || !validID(job.UploadID) || job.ClaimOwner == "" || job.ClaimEpoch < 1 || !allowed[code] {
		return ErrInvalidRecord
	}
	state := "retryable"
	if permanent || code == "malware_detected" || code == "unsupported_content" || job.Attempt >= maxJobAttempts {
		state = "rejected"
	}
	return tenancy.WithTenantTx(ctx, r.db, job.TenantID, nil, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE keel_meta.supplier_uploads
			SET upload_state=$1,last_error_code=$2,processed_at=CASE WHEN $1='rejected' THEN $3 ELSE NULL END,
				claim_owner=NULL,lease_until=NULL,updated_at=$3
			WHERE tenant_id=$4 AND upload_id=$5 AND upload_state='scanning' AND claim_owner=$6 AND claim_epoch=$7 AND lease_until>$3`,
			state, code, now.UTC(), string(job.TenantID), job.UploadID, job.ClaimOwner, job.ClaimEpoch)
		if err != nil {
			return errors.New("supplier upload failure state could not be recorded")
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			return ErrConflict
		}
		return nil
	})
}

func validID(value string) bool {
	if len(value) != 36 || strings.ToLower(value) != value {
		return false
	}
	if _, err := tenancy.ParseTenantID(value); err != nil {
		return false
	}
	return true
}

func intakeFormat(value intake.Format) bool {
	return value == intake.FormatPDF || value == intake.FormatDOCX || value == intake.FormatText
}

func UUID(source io.Reader) (string, error) {
	if source == nil {
		source = rand.Reader
	}
	var b [16]byte
	if _, err := io.ReadFull(source, b[:]); err != nil {
		return "", errors.New("secure ID generation failed")
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
