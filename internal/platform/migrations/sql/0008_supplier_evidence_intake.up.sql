-- Supplier bearer tokens are hashed; uploads remain opaque, quarantined objects until the
-- constrained scanner/extractor worker records a clean, bounded result.
CREATE TABLE keel_meta.supplier_invitations (
    tenant_id uuid NOT NULL,
    invitation_id uuid NOT NULL,
    case_id uuid NOT NULL,
    supplier_id uuid NOT NULL,
    recipient_digest bytea NOT NULL CHECK (octet_length(recipient_digest) = 32),
    invitation_token_digest bytea NOT NULL CHECK (octet_length(invitation_token_digest) = 32),
    invitation_state text NOT NULL CHECK (invitation_state IN ('pending', 'accepted', 'revoked', 'expired')),
    issued_by_ref text NOT NULL CHECK (issued_by_ref ~ '^(principal|service-principal):[A-Za-z0-9._~-]{1,120}$'),
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, invitation_id),
    UNIQUE (tenant_id, invitation_token_digest),
    CHECK ((invitation_state = 'accepted') = (accepted_at IS NOT NULL)),
    CHECK ((invitation_state = 'revoked') = (revoked_at IS NOT NULL)),
    CHECK (expires_at > created_at)
);
CREATE INDEX supplier_invitations_case_idx
    ON keel_meta.supplier_invitations (tenant_id, case_id, created_at DESC);

CREATE TABLE keel_meta.supplier_upload_sessions (
    tenant_id uuid NOT NULL,
    session_id uuid NOT NULL,
    invitation_id uuid NOT NULL,
    session_token_digest bytea NOT NULL CHECK (octet_length(session_token_digest) = 32),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, session_id),
    UNIQUE (session_token_digest),
    FOREIGN KEY (tenant_id, invitation_id)
        REFERENCES keel_meta.supplier_invitations (tenant_id, invitation_id)
);
CREATE INDEX supplier_upload_sessions_invitation_idx
    ON keel_meta.supplier_upload_sessions (tenant_id, invitation_id, expires_at);

CREATE TABLE keel_meta.supplier_uploads (
    tenant_id uuid NOT NULL,
    upload_id uuid NOT NULL,
    invitation_id uuid NOT NULL,
    session_id uuid NOT NULL,
    object_key uuid NOT NULL,
    declared_media_type text NOT NULL CHECK (declared_media_type IN (
        'application/pdf',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'text/plain'
    )),
    expected_bytes bigint NOT NULL CHECK (expected_bytes BETWEEN 1 AND 20971520),
    expected_sha256 bytea NOT NULL CHECK (octet_length(expected_sha256) = 32),
    upload_expires_at timestamptz NOT NULL,
    upload_state text NOT NULL CHECK (upload_state IN (
        'awaiting_upload', 'queued', 'scanning', 'extracted', 'rejected', 'retryable', 'expired'
    )),
    detected_media_type text,
    scanner_version text,
    scanned_at timestamptz,
    extracted_object_key uuid,
    extracted_bytes bigint CHECK (extracted_bytes IS NULL OR extracted_bytes BETWEEN 0 AND 4194304),
    extracted_sha256 bytea CHECK (extracted_sha256 IS NULL OR octet_length(extracted_sha256) = 32),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    claim_epoch bigint NOT NULL DEFAULT 0 CHECK (claim_epoch >= 0),
    claim_owner text,
    lease_until timestamptz,
    last_error_code text CHECK (last_error_code IS NULL OR last_error_code IN (
        'malware_detected', 'unsupported_content', 'scanner_unavailable', 'extraction_failed', 'output_limit'
    )),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    uploaded_at timestamptz,
    processed_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, upload_id),
    UNIQUE (object_key),
    FOREIGN KEY (tenant_id, invitation_id)
        REFERENCES keel_meta.supplier_invitations (tenant_id, invitation_id),
    FOREIGN KEY (tenant_id, session_id)
        REFERENCES keel_meta.supplier_upload_sessions (tenant_id, session_id),
    CHECK ((upload_state IN ('awaiting_upload', 'expired')) = (uploaded_at IS NULL)),
    CHECK ((upload_state IN ('awaiting_upload', 'expired')) = (detected_media_type IS NULL)),
    CHECK (detected_media_type IS NULL OR detected_media_type = declared_media_type),
    CHECK ((upload_state = 'extracted') = (extracted_object_key IS NOT NULL AND extracted_sha256 IS NOT NULL AND processed_at IS NOT NULL)),
    CHECK (extracted_object_key IS NULL OR extracted_object_key <> object_key),
    CHECK ((upload_state = 'extracted') = (scanner_version IS NOT NULL AND scanned_at IS NOT NULL AND extracted_bytes IS NOT NULL)),
    CHECK ((scanner_version IS NULL AND scanned_at IS NULL AND extracted_bytes IS NULL) OR
           (scanner_version IS NOT NULL AND scanned_at IS NOT NULL AND extracted_bytes IS NOT NULL)),
    CHECK ((upload_state = 'scanning') = (claim_owner IS NOT NULL AND lease_until IS NOT NULL)),
    CHECK ((upload_state IN ('rejected', 'retryable')) = (last_error_code IS NOT NULL)),
    CHECK ((upload_state IN ('extracted', 'rejected')) = (processed_at IS NOT NULL))
);
CREATE INDEX supplier_uploads_worker_idx
    ON keel_meta.supplier_uploads (tenant_id, created_at, upload_id)
    WHERE upload_state IN ('queued', 'retryable', 'scanning');
CREATE INDEX supplier_uploads_invitation_idx
    ON keel_meta.supplier_uploads (tenant_id, invitation_id, created_at DESC);

ALTER TABLE keel_meta.supplier_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.supplier_invitations FORCE ROW LEVEL SECURITY;
CREATE POLICY supplier_invitations_tenant_isolation ON keel_meta.supplier_invitations
    TO keel_app, keel_file_processor
    USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));

ALTER TABLE keel_meta.supplier_upload_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.supplier_upload_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY supplier_upload_sessions_tenant_isolation ON keel_meta.supplier_upload_sessions
    TO keel_app, keel_file_processor
    USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));

ALTER TABLE keel_meta.supplier_uploads ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.supplier_uploads FORCE ROW LEVEL SECURITY;
CREATE POLICY supplier_uploads_tenant_isolation ON keel_meta.supplier_uploads
    TO keel_app, keel_file_processor
    USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));

REVOKE ALL ON keel_meta.supplier_invitations, keel_meta.supplier_upload_sessions, keel_meta.supplier_uploads FROM PUBLIC, keel_agent, keel_worker, keel_projector, keel_operator;
GRANT USAGE ON SCHEMA keel_meta TO keel_app, keel_file_processor;
GRANT SELECT, INSERT ON keel_meta.supplier_invitations TO keel_app;
GRANT UPDATE (invitation_state, accepted_at, revoked_at, updated_at) ON keel_meta.supplier_invitations TO keel_app;
GRANT SELECT, INSERT ON keel_meta.supplier_upload_sessions TO keel_app;
GRANT SELECT, INSERT ON keel_meta.supplier_uploads TO keel_app;
GRANT UPDATE (upload_state, uploaded_at, detected_media_type, upload_expires_at, updated_at) ON keel_meta.supplier_uploads TO keel_app;
GRANT SELECT ON keel_meta.supplier_uploads TO keel_file_processor;
GRANT UPDATE (upload_state, detected_media_type, scanner_version, scanned_at,
    extracted_object_key, extracted_bytes, extracted_sha256, attempt_count,
    claim_epoch, claim_owner, lease_until, last_error_code, processed_at, updated_at)
    ON keel_meta.supplier_uploads TO keel_file_processor;
