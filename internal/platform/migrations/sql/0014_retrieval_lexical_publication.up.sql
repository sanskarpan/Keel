-- K3.2: tenant/cohort-local lexical corpus builds and atomic publication.
CREATE TABLE keel_meta.retrieval_corpus_builds (
    tenant_id uuid NOT NULL,
    build_id uuid NOT NULL,
    visibility_key text NOT NULL CHECK (visibility_key ~ '^[a-z0-9][a-z0-9._:-]{1,63}$'),
    analyzer_id text NOT NULL CHECK (analyzer_id ~ '^[a-z0-9][a-z0-9._:-]{1,159}$'),
    chunker_id text NOT NULL CHECK (chunker_id ~ '^[a-z0-9][a-z0-9._:-]{1,159}$'),
    term_key_id text NOT NULL CHECK (term_key_id ~ '^[a-z0-9][a-z0-9._:-]{1,159}$'),
    manifest_sha256 bytea NOT NULL CHECK (octet_length(manifest_sha256)=32),
    expected_chunk_count integer NOT NULL CHECK (expected_chunk_count BETWEEN 1 AND 100000),
    state text NOT NULL DEFAULT 'building' CHECK (state IN ('building','ready','published','retired','failed')),
    chunk_count integer NOT NULL DEFAULT 0 CHECK (chunk_count BETWEEN 0 AND 100000),
    total_token_count bigint NOT NULL DEFAULT 0 CHECK (total_token_count BETWEEN 0 AND 100000000),
    term_count integer NOT NULL DEFAULT 0 CHECK (term_count BETWEEN 0 AND 10000000),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    ready_at timestamptz,
    published_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,build_id),
    UNIQUE (tenant_id,build_id,visibility_key),
    UNIQUE (tenant_id,build_id,visibility_key,term_key_id),
    CHECK ((state='building' AND ready_at IS NULL AND published_at IS NULL) OR
           (state='ready' AND ready_at IS NOT NULL AND published_at IS NULL) OR
           (state='published' AND ready_at IS NOT NULL AND published_at IS NOT NULL) OR
           (state='retired' AND ready_at IS NOT NULL AND published_at IS NOT NULL) OR
           (state='failed' AND published_at IS NULL))
);

CREATE TABLE keel_meta.retrieval_corpus_heads (
    tenant_id uuid NOT NULL,
    visibility_key text NOT NULL CHECK (visibility_key ~ '^[a-z0-9][a-z0-9._:-]{1,63}$'),
    active_build_id uuid,
    generation bigint NOT NULL DEFAULT 0 CHECK (generation>=0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,visibility_key),
    FOREIGN KEY (tenant_id,active_build_id,visibility_key)
        REFERENCES keel_meta.retrieval_corpus_builds (tenant_id,build_id,visibility_key)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK ((active_build_id IS NULL AND generation=0) OR (active_build_id IS NOT NULL AND generation>0))
);

CREATE TABLE keel_meta.retrieval_chunks (
    tenant_id uuid NOT NULL,
    build_id uuid NOT NULL,
    visibility_key text NOT NULL,
    chunk_id uuid NOT NULL,
    document_version_id uuid NOT NULL,
    chunk_ordinal integer NOT NULL CHECK (chunk_ordinal BETWEEN 0 AND 99999),
    source_start_byte integer NOT NULL CHECK (source_start_byte>=0),
    source_end_byte integer NOT NULL CHECK (source_end_byte>source_start_byte),
    token_count integer NOT NULL CHECK (token_count BETWEEN 1 AND 2048),
    content_sha256 bytea NOT NULL CHECK (octet_length(content_sha256)=32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,build_id,chunk_id),
    UNIQUE (tenant_id,build_id,document_version_id,chunk_ordinal),
    FOREIGN KEY (tenant_id,build_id,visibility_key)
        REFERENCES keel_meta.retrieval_corpus_builds (tenant_id,build_id,visibility_key)
);

CREATE TABLE keel_meta.retrieval_term_postings (
    tenant_id uuid NOT NULL,
    build_id uuid NOT NULL,
    visibility_key text NOT NULL,
    term_key_id text NOT NULL,
    term_id bytea NOT NULL CHECK (octet_length(term_id)=32),
    chunk_id uuid NOT NULL,
    term_frequency smallint NOT NULL CHECK (term_frequency BETWEEN 1 AND 2048),
    PRIMARY KEY (tenant_id,build_id,term_id,chunk_id),
    FOREIGN KEY (tenant_id,build_id,visibility_key,term_key_id)
        REFERENCES keel_meta.retrieval_corpus_builds (tenant_id,build_id,visibility_key,term_key_id),
    FOREIGN KEY (tenant_id,build_id,chunk_id)
        REFERENCES keel_meta.retrieval_chunks (tenant_id,build_id,chunk_id)
);
CREATE INDEX retrieval_term_postings_chunk_idx
    ON keel_meta.retrieval_term_postings (tenant_id,build_id,chunk_id);

CREATE TABLE keel_meta.retrieval_term_statistics (
    tenant_id uuid NOT NULL,
    build_id uuid NOT NULL,
    visibility_key text NOT NULL,
    term_key_id text NOT NULL,
    term_id bytea NOT NULL CHECK (octet_length(term_id)=32),
    document_frequency integer NOT NULL CHECK (document_frequency BETWEEN 1 AND 100000),
    PRIMARY KEY (tenant_id,build_id,term_id),
    FOREIGN KEY (tenant_id,build_id,visibility_key,term_key_id)
        REFERENCES keel_meta.retrieval_corpus_builds (tenant_id,build_id,visibility_key,term_key_id)
);

CREATE INDEX retrieval_corpus_builds_scope_state_idx
    ON keel_meta.retrieval_corpus_builds (tenant_id,visibility_key,state,created_at);

CREATE OR REPLACE FUNCTION keel_meta.guard_retrieval_build_state()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE actual_chunks bigint; actual_tokens bigint; actual_terms bigint; bad_rows bigint;
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.state<>'building' OR NEW.chunk_count<>0 OR NEW.total_token_count<>0 OR NEW.term_count<>0 OR
           NEW.ready_at IS NOT NULL OR NEW.published_at IS NOT NULL THEN
            RAISE EXCEPTION 'retrieval builds must begin empty in building state';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.tenant_id<>OLD.tenant_id OR NEW.build_id<>OLD.build_id OR NEW.visibility_key<>OLD.visibility_key OR
       NEW.analyzer_id<>OLD.analyzer_id OR NEW.chunker_id<>OLD.chunker_id OR NEW.term_key_id<>OLD.term_key_id OR
       NEW.manifest_sha256<>OLD.manifest_sha256 OR NEW.expected_chunk_count<>OLD.expected_chunk_count OR
       NEW.created_at<>OLD.created_at THEN
        RAISE EXCEPTION 'retrieval build identity and expected input are immutable';
    END IF;
    IF NEW.state=OLD.state THEN
        IF OLD.state<>'building' OR NEW.ready_at IS NOT NULL OR NEW.published_at IS NOT NULL OR
           NEW.chunk_count<>OLD.chunk_count OR NEW.total_token_count<>OLD.total_token_count OR NEW.term_count<>OLD.term_count THEN
            RAISE EXCEPTION 'only building retrieval manifests may be edited';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.state='building' AND NEW.state IN ('ready','failed') THEN
        IF NEW.state='failed' THEN
            IF NEW.ready_at IS NOT NULL OR NEW.published_at IS NOT NULL THEN RAISE EXCEPTION 'failed build timestamps invalid'; END IF;
            RETURN NEW;
        END IF;
        SELECT count(*),coalesce(sum(token_count),0) INTO actual_chunks,actual_tokens
          FROM keel_meta.retrieval_chunks WHERE tenant_id=NEW.tenant_id AND build_id=NEW.build_id;
        SELECT count(*) INTO actual_terms FROM keel_meta.retrieval_term_statistics
          WHERE tenant_id=NEW.tenant_id AND build_id=NEW.build_id;
        IF actual_chunks<>NEW.expected_chunk_count OR NEW.chunk_count<>actual_chunks OR NEW.total_token_count<>actual_tokens OR NEW.term_count<>actual_terms OR actual_terms=0 THEN
            RAISE EXCEPTION 'retrieval build manifest counts do not match staged rows';
        END IF;
        SELECT count(*) INTO bad_rows FROM (
          SELECT c.chunk_id,c.token_count,coalesce(sum(p.term_frequency),0) AS tf
          FROM keel_meta.retrieval_chunks c LEFT JOIN keel_meta.retrieval_term_postings p
            ON p.tenant_id=c.tenant_id AND p.build_id=c.build_id AND p.chunk_id=c.chunk_id
          WHERE c.tenant_id=NEW.tenant_id AND c.build_id=NEW.build_id
          GROUP BY c.chunk_id,c.token_count HAVING coalesce(sum(p.term_frequency),0)<>c.token_count
        ) invalid_chunks;
        IF bad_rows<>0 THEN RAISE EXCEPTION 'retrieval posting frequencies do not reconcile to chunk lengths'; END IF;
        SELECT count(*) INTO bad_rows FROM (
          SELECT s.term_id,s.document_frequency,count(p.chunk_id) AS actual_df
          FROM keel_meta.retrieval_term_statistics s LEFT JOIN keel_meta.retrieval_term_postings p
            ON p.tenant_id=s.tenant_id AND p.build_id=s.build_id AND p.term_id=s.term_id
          WHERE s.tenant_id=NEW.tenant_id AND s.build_id=NEW.build_id
          GROUP BY s.term_id,s.document_frequency HAVING s.document_frequency<>count(p.chunk_id)
          UNION ALL
          SELECT p.term_id,0,count(*) FROM keel_meta.retrieval_term_postings p
          LEFT JOIN keel_meta.retrieval_term_statistics s
            ON s.tenant_id=p.tenant_id AND s.build_id=p.build_id AND s.term_id=p.term_id
          WHERE p.tenant_id=NEW.tenant_id AND p.build_id=NEW.build_id AND s.term_id IS NULL
          GROUP BY p.term_id
        ) invalid_statistics;
        IF bad_rows<>0 THEN RAISE EXCEPTION 'retrieval term statistics do not reconcile to postings'; END IF;
        IF NEW.ready_at IS NULL OR NEW.published_at IS NOT NULL THEN RAISE EXCEPTION 'retrieval ready timestamp shape invalid'; END IF;
        RETURN NEW;
    END IF;
    IF OLD.state='ready' AND NEW.state IN ('published','failed') THEN
        IF NEW.state='published' THEN
            IF NEW.chunk_count<>OLD.chunk_count OR NEW.total_token_count<>OLD.total_token_count OR NEW.term_count<>OLD.term_count THEN
                RAISE EXCEPTION 'validated retrieval build counts are immutable';
            END IF;
            IF NOT EXISTS (SELECT 1 FROM keel_meta.retrieval_corpus_heads h WHERE h.tenant_id=NEW.tenant_id
                AND h.visibility_key=NEW.visibility_key AND h.active_build_id=NEW.build_id) THEN
                RAISE EXCEPTION 'retrieval build must be the active head before publication';
            END IF;
            IF NEW.published_at IS NULL OR NEW.ready_at<>OLD.ready_at THEN RAISE EXCEPTION 'retrieval publication timestamp shape invalid'; END IF;
        ELSIF NEW.ready_at<>OLD.ready_at OR NEW.published_at IS NOT NULL THEN
            RAISE EXCEPTION 'failed ready build timestamp shape invalid';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.state='published' AND NEW.state='retired' THEN
        IF NEW.chunk_count<>OLD.chunk_count OR NEW.total_token_count<>OLD.total_token_count OR NEW.term_count<>OLD.term_count THEN
            RAISE EXCEPTION 'published retrieval build counts are immutable';
        END IF;
        IF EXISTS (SELECT 1 FROM keel_meta.retrieval_corpus_heads h WHERE h.tenant_id=OLD.tenant_id AND h.active_build_id=OLD.build_id) THEN
            RAISE EXCEPTION 'active retrieval build cannot be retired';
        END IF;
        IF NEW.ready_at<>OLD.ready_at OR NEW.published_at<>OLD.published_at THEN RAISE EXCEPTION 'published build timestamps are immutable'; END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid retrieval build state transition: % -> %',OLD.state,NEW.state;
END $$;

CREATE OR REPLACE FUNCTION keel_meta.guard_retrieval_staged_row()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE t uuid; b uuid; s text;
BEGIN
    t:=CASE WHEN TG_OP='DELETE' THEN OLD.tenant_id ELSE NEW.tenant_id END;
    b:=CASE WHEN TG_OP='DELETE' THEN OLD.build_id ELSE NEW.build_id END;
    SELECT state INTO s FROM keel_meta.retrieval_corpus_builds WHERE tenant_id=t AND build_id=b FOR KEY SHARE;
    IF TG_OP='DELETE' AND s IN ('building','failed') THEN RETURN OLD; END IF;
    IF TG_OP<>'DELETE' AND s='building' THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'retrieval chunks/postings/statistics may only be inserted while building and deleted while building or failed';
END $$;

CREATE TRIGGER retrieval_build_state_guard BEFORE INSERT OR UPDATE ON keel_meta.retrieval_corpus_builds
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_retrieval_build_state();

CREATE OR REPLACE FUNCTION keel_meta.guard_retrieval_corpus_head()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE build_state text; build_visibility text;
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.active_build_id IS NOT NULL OR NEW.generation<>0 THEN RAISE EXCEPTION 'retrieval corpus head must begin empty'; END IF;
        RETURN NEW;
    END IF;
    IF NEW.tenant_id<>OLD.tenant_id OR NEW.visibility_key<>OLD.visibility_key OR NEW.generation<>OLD.generation+1 OR NEW.active_build_id IS NULL THEN
        RAISE EXCEPTION 'retrieval corpus publication must advance one generation for the same cohort';
    END IF;
    SELECT state,visibility_key INTO build_state,build_visibility FROM keel_meta.retrieval_corpus_builds
      WHERE tenant_id=NEW.tenant_id AND build_id=NEW.active_build_id FOR KEY SHARE;
    IF build_state<>'ready' OR build_visibility<>NEW.visibility_key THEN
        RAISE EXCEPTION 'only a validated ready build for this cohort can be published';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER retrieval_corpus_head_guard BEFORE INSERT OR UPDATE ON keel_meta.retrieval_corpus_heads
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_retrieval_corpus_head();
CREATE TRIGGER retrieval_chunks_staging_guard BEFORE INSERT OR UPDATE OR DELETE ON keel_meta.retrieval_chunks
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_retrieval_staged_row();
CREATE TRIGGER retrieval_postings_staging_guard BEFORE INSERT OR UPDATE OR DELETE ON keel_meta.retrieval_term_postings
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_retrieval_staged_row();
CREATE TRIGGER retrieval_statistics_staging_guard BEFORE INSERT OR UPDATE OR DELETE ON keel_meta.retrieval_term_statistics
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_retrieval_staged_row();
REVOKE ALL ON FUNCTION keel_meta.guard_retrieval_build_state(),
    keel_meta.guard_retrieval_corpus_head(),keel_meta.guard_retrieval_staged_row() FROM PUBLIC;

ALTER TABLE keel_meta.retrieval_corpus_builds ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.retrieval_corpus_builds FORCE ROW LEVEL SECURITY;
CREATE POLICY retrieval_builds_scope ON keel_meta.retrieval_corpus_builds TO keel_app,keel_retrieval_indexer
    USING (tenant_id=(SELECT keel_private.current_tenant_id()) AND visibility_key=nullif(current_setting('keel.visibility_key',true),''))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()) AND visibility_key=nullif(current_setting('keel.visibility_key',true),''));
ALTER TABLE keel_meta.retrieval_corpus_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.retrieval_corpus_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY retrieval_heads_scope ON keel_meta.retrieval_corpus_heads TO keel_app,keel_retrieval_indexer
    USING (tenant_id=(SELECT keel_private.current_tenant_id()) AND visibility_key=nullif(current_setting('keel.visibility_key',true),''))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()) AND visibility_key=nullif(current_setting('keel.visibility_key',true),''));
ALTER TABLE keel_meta.retrieval_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.retrieval_chunks FORCE ROW LEVEL SECURITY;
CREATE POLICY retrieval_chunks_scope ON keel_meta.retrieval_chunks TO keel_app,keel_retrieval_indexer
    USING (tenant_id=(SELECT keel_private.current_tenant_id()) AND visibility_key=nullif(current_setting('keel.visibility_key',true),''))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()) AND visibility_key=nullif(current_setting('keel.visibility_key',true),''));
ALTER TABLE keel_meta.retrieval_term_postings ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.retrieval_term_postings FORCE ROW LEVEL SECURITY;
CREATE POLICY retrieval_postings_scope ON keel_meta.retrieval_term_postings TO keel_app,keel_retrieval_indexer
    USING (tenant_id=(SELECT keel_private.current_tenant_id()) AND visibility_key=nullif(current_setting('keel.visibility_key',true),''))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()) AND visibility_key=nullif(current_setting('keel.visibility_key',true),''));
ALTER TABLE keel_meta.retrieval_term_statistics ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.retrieval_term_statistics FORCE ROW LEVEL SECURITY;
CREATE POLICY retrieval_statistics_scope ON keel_meta.retrieval_term_statistics TO keel_app,keel_retrieval_indexer
    USING (tenant_id=(SELECT keel_private.current_tenant_id()) AND visibility_key=nullif(current_setting('keel.visibility_key',true),''))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()) AND visibility_key=nullif(current_setting('keel.visibility_key',true),''));

REVOKE ALL ON keel_meta.retrieval_corpus_builds,keel_meta.retrieval_corpus_heads,keel_meta.retrieval_chunks,
    keel_meta.retrieval_term_postings,keel_meta.retrieval_term_statistics FROM PUBLIC,keel_app,keel_agent,keel_worker,keel_projector,keel_operator,keel_file_processor;
GRANT USAGE ON SCHEMA keel_private,keel_meta TO keel_retrieval_indexer;
GRANT EXECUTE ON FUNCTION keel_private.current_tenant_id() TO keel_retrieval_indexer;
GRANT SELECT ON keel_meta.retrieval_corpus_builds,keel_meta.retrieval_corpus_heads,keel_meta.retrieval_chunks,
    keel_meta.retrieval_term_postings,keel_meta.retrieval_term_statistics TO keel_app;
GRANT SELECT,INSERT ON keel_meta.retrieval_corpus_builds,keel_meta.retrieval_corpus_heads TO keel_retrieval_indexer;
GRANT UPDATE (state,chunk_count,total_token_count,term_count,ready_at,published_at,updated_at)
    ON keel_meta.retrieval_corpus_builds TO keel_retrieval_indexer;
GRANT UPDATE (active_build_id,generation,updated_at) ON keel_meta.retrieval_corpus_heads TO keel_retrieval_indexer;
GRANT SELECT,INSERT,DELETE ON keel_meta.retrieval_chunks,keel_meta.retrieval_term_postings,keel_meta.retrieval_term_statistics TO keel_retrieval_indexer;
