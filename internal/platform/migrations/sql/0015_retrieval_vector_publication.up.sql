-- K3.3: immutable vector-model manifests and corpus-generation-bound vector builds.
CREATE TABLE keel_meta.retrieval_model_manifests (
    model_id text NOT NULL CHECK (model_id ~ '^[a-z0-9][a-z0-9._:-]{1,159}$'),
    model_revision text NOT NULL CHECK (model_revision ~ '^[a-z0-9][a-z0-9._:-]{1,159}$'),
    provider_id text NOT NULL CHECK (provider_id ~ '^[a-z0-9][a-z0-9._:-]{1,159}$'),
    artifact_sha256 bytea NOT NULL CHECK (octet_length(artifact_sha256)=32),
    tokenizer_id text NOT NULL CHECK (tokenizer_id ~ '^[a-z0-9][a-z0-9._:-]{1,159}$'),
    analyzer_id text NOT NULL CHECK (analyzer_id ~ '^[a-z0-9][a-z0-9._:-]{1,159}$'),
    max_input_tokens integer NOT NULL CHECK (max_input_tokens BETWEEN 1 AND 1000000),
    dimensions integer NOT NULL CHECK (dimensions BETWEEN 1 AND 16000),
    distance_metric text NOT NULL CHECK (distance_metric='cosine'),
    normalization text NOT NULL CHECK (normalization='unit_l2'),
    manifest_sha256 bytea NOT NULL CHECK (octet_length(manifest_sha256)=32),
    hnsw_index_name name,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (model_id,model_revision),
    UNIQUE (model_id,model_revision,manifest_sha256)
);

CREATE OR REPLACE FUNCTION keel_meta.reject_retrieval_model_manifest_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta,pg_temp AS $$
BEGIN
	IF TG_OP='UPDATE' AND OLD.hnsw_index_name IS NULL AND NEW.hnsw_index_name IS NOT NULL AND
	   NEW.model_id=OLD.model_id AND NEW.model_revision=OLD.model_revision AND NEW.provider_id=OLD.provider_id AND
	   NEW.artifact_sha256=OLD.artifact_sha256 AND NEW.tokenizer_id=OLD.tokenizer_id AND NEW.analyzer_id=OLD.analyzer_id AND
	   NEW.max_input_tokens=OLD.max_input_tokens AND NEW.dimensions=OLD.dimensions AND NEW.distance_metric=OLD.distance_metric AND
	   NEW.normalization=OLD.normalization AND NEW.manifest_sha256=OLD.manifest_sha256 AND NEW.created_at=OLD.created_at THEN
		RETURN NEW;
	END IF;
    RAISE EXCEPTION 'retrieval model manifests are immutable; register a new model ID or revision';
END $$;
CREATE TRIGGER retrieval_model_manifest_immutable BEFORE UPDATE OR DELETE ON keel_meta.retrieval_model_manifests
    FOR EACH ROW EXECUTE FUNCTION keel_meta.reject_retrieval_model_manifest_mutation();
REVOKE ALL ON FUNCTION keel_meta.reject_retrieval_model_manifest_mutation() FROM PUBLIC;

CREATE TABLE keel_meta.retrieval_vector_builds (
    tenant_id uuid NOT NULL,
    vector_build_id uuid NOT NULL,
    visibility_key text NOT NULL CHECK (visibility_key ~ '^[a-z0-9][a-z0-9._:-]{1,63}$'),
    corpus_build_id uuid NOT NULL,
    corpus_generation bigint NOT NULL CHECK (corpus_generation>0),
    model_id text NOT NULL,
    model_revision text NOT NULL,
    manifest_sha256 bytea NOT NULL CHECK (octet_length(manifest_sha256)=32),
    expected_chunk_count integer NOT NULL CHECK (expected_chunk_count BETWEEN 1 AND 100000),
    vector_count integer NOT NULL DEFAULT 0 CHECK (vector_count BETWEEN 0 AND 100000),
    state text NOT NULL DEFAULT 'building' CHECK (state IN ('building','ready','published','retired','failed')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    ready_at timestamptz,
    published_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,vector_build_id),
    UNIQUE (tenant_id,vector_build_id,visibility_key),
    UNIQUE (tenant_id,vector_build_id,corpus_build_id,visibility_key),
    UNIQUE (tenant_id,vector_build_id,visibility_key,model_id,model_revision),
    FOREIGN KEY (tenant_id,corpus_build_id,visibility_key)
        REFERENCES keel_meta.retrieval_corpus_builds (tenant_id,build_id,visibility_key),
    FOREIGN KEY (model_id,model_revision,manifest_sha256)
        REFERENCES keel_meta.retrieval_model_manifests (model_id,model_revision,manifest_sha256),
    CHECK ((state='building' AND ready_at IS NULL AND published_at IS NULL) OR
           (state='ready' AND ready_at IS NOT NULL AND published_at IS NULL) OR
           (state='published' AND ready_at IS NOT NULL AND published_at IS NOT NULL) OR
           (state='retired' AND ready_at IS NOT NULL AND published_at IS NOT NULL) OR
           (state='failed' AND published_at IS NULL))
);

CREATE TABLE keel_meta.retrieval_vector_heads (
    tenant_id uuid NOT NULL,
    visibility_key text NOT NULL CHECK (visibility_key ~ '^[a-z0-9][a-z0-9._:-]{1,63}$'),
    model_id text NOT NULL,
    model_revision text NOT NULL,
    active_vector_build_id uuid,
    generation bigint NOT NULL DEFAULT 0 CHECK (generation>=0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,visibility_key,model_id,model_revision),
    FOREIGN KEY (tenant_id,active_vector_build_id,visibility_key,model_id,model_revision)
        REFERENCES keel_meta.retrieval_vector_builds (tenant_id,vector_build_id,visibility_key,model_id,model_revision)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK ((active_vector_build_id IS NULL AND generation=0) OR (active_vector_build_id IS NOT NULL AND generation>0))
);

CREATE TABLE keel_meta.retrieval_vector_chunks (
    tenant_id uuid NOT NULL,
    vector_build_id uuid NOT NULL,
    visibility_key text NOT NULL,
    corpus_build_id uuid NOT NULL,
    model_id text NOT NULL,
    model_revision text NOT NULL,
    chunk_id uuid NOT NULL,
    model_input_tokens integer NOT NULL CHECK (model_input_tokens BETWEEN 1 AND 1000000),
    embedding public.vector NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,vector_build_id,chunk_id),
    FOREIGN KEY (tenant_id,vector_build_id,visibility_key,model_id,model_revision)
        REFERENCES keel_meta.retrieval_vector_builds (tenant_id,vector_build_id,visibility_key,model_id,model_revision),
    FOREIGN KEY (tenant_id,vector_build_id,corpus_build_id,visibility_key)
        REFERENCES keel_meta.retrieval_vector_builds (tenant_id,vector_build_id,corpus_build_id,visibility_key),
    FOREIGN KEY (tenant_id,corpus_build_id,chunk_id)
        REFERENCES keel_meta.retrieval_chunks (tenant_id,build_id,chunk_id)
);
CREATE INDEX retrieval_vector_chunks_scope_idx
    ON keel_meta.retrieval_vector_chunks (tenant_id,visibility_key,model_id,model_revision,vector_build_id,chunk_id);

CREATE OR REPLACE FUNCTION keel_meta.guard_retrieval_vector_embedding()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE expected_dims integer; max_input_tokens integer; actual_norm double precision;
BEGIN
    SELECT m.dimensions,m.max_input_tokens INTO expected_dims,max_input_tokens
      FROM keel_meta.retrieval_vector_builds b JOIN keel_meta.retrieval_model_manifests m
        ON m.model_id=b.model_id AND m.model_revision=b.model_revision AND m.manifest_sha256=b.manifest_sha256
     WHERE b.tenant_id=NEW.tenant_id AND b.vector_build_id=NEW.vector_build_id;
    IF expected_dims IS NULL OR public.vector_dims(NEW.embedding)<>expected_dims THEN
        RAISE EXCEPTION 'embedding dimension differs from immutable model manifest';
    END IF;
    IF NEW.model_input_tokens<1 OR NEW.model_input_tokens>max_input_tokens THEN
        RAISE EXCEPTION 'embedding input exceeds immutable model input-token bound';
    END IF;
    actual_norm:=public.vector_norm(NEW.embedding);
    IF actual_norm<0.000000000001 OR abs(actual_norm-1.0)>0.001 THEN
        RAISE EXCEPTION 'embedding must be nonzero and unit-normalized';
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION keel_meta.guard_retrieval_vector_staged_row()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE t uuid; b uuid; s text;
BEGIN
    t:=CASE WHEN TG_OP='DELETE' THEN OLD.tenant_id ELSE NEW.tenant_id END;
    b:=CASE WHEN TG_OP='DELETE' THEN OLD.vector_build_id ELSE NEW.vector_build_id END;
    SELECT state INTO s FROM keel_meta.retrieval_vector_builds WHERE tenant_id=t AND vector_build_id=b FOR KEY SHARE;
    IF TG_OP='DELETE' AND s IN ('building','failed') THEN RETURN OLD; END IF;
    IF TG_OP<>'DELETE' AND s='building' THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'retrieval vectors may only be inserted while building and deleted while building or failed';
END $$;

CREATE OR REPLACE FUNCTION keel_meta.guard_retrieval_vector_build_state()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE actual_vectors bigint; lexical_count integer; lexical_state text; active_corpus uuid; active_corpus_generation bigint;
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.state<>'building' OR NEW.vector_count<>0 OR NEW.ready_at IS NOT NULL OR NEW.published_at IS NOT NULL THEN
            RAISE EXCEPTION 'vector builds must begin empty in building state';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM keel_meta.retrieval_corpus_builds c JOIN keel_meta.retrieval_model_manifests m
            ON m.model_id=NEW.model_id AND m.model_revision=NEW.model_revision AND m.manifest_sha256=NEW.manifest_sha256
            WHERE c.tenant_id=NEW.tenant_id AND c.build_id=NEW.corpus_build_id AND c.visibility_key=NEW.visibility_key
              AND c.state='published' AND c.analyzer_id=m.analyzer_id AND c.chunk_count=NEW.expected_chunk_count) THEN
            RAISE EXCEPTION 'vector build must bind to a published compatible corpus in the same cohort';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.tenant_id<>OLD.tenant_id OR NEW.vector_build_id<>OLD.vector_build_id OR NEW.visibility_key<>OLD.visibility_key OR
       NEW.corpus_build_id<>OLD.corpus_build_id OR NEW.corpus_generation<>OLD.corpus_generation OR NEW.model_id<>OLD.model_id OR
       NEW.model_revision<>OLD.model_revision OR NEW.manifest_sha256<>OLD.manifest_sha256 OR
       NEW.expected_chunk_count<>OLD.expected_chunk_count OR NEW.created_at<>OLD.created_at THEN
        RAISE EXCEPTION 'vector build identity and source snapshot are immutable';
    END IF;
    IF NEW.state=OLD.state THEN
        IF OLD.state<>'building' OR NEW.ready_at IS NOT NULL OR NEW.published_at IS NOT NULL OR NEW.vector_count<>OLD.vector_count THEN
            RAISE EXCEPTION 'only building vector manifests may be edited';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.state='building' AND NEW.state IN ('ready','failed') THEN
        IF NEW.state='failed' THEN
            IF NEW.ready_at IS NOT NULL OR NEW.published_at IS NOT NULL THEN RAISE EXCEPTION 'failed vector timestamps invalid'; END IF;
            RETURN NEW;
        END IF;
        SELECT count(*) INTO actual_vectors FROM keel_meta.retrieval_vector_chunks
          WHERE tenant_id=NEW.tenant_id AND vector_build_id=NEW.vector_build_id;
        SELECT chunk_count,state INTO lexical_count,lexical_state FROM keel_meta.retrieval_corpus_builds
          WHERE tenant_id=NEW.tenant_id AND build_id=NEW.corpus_build_id AND visibility_key=NEW.visibility_key;
        IF actual_vectors<>NEW.expected_chunk_count OR NEW.vector_count<>actual_vectors OR lexical_state<>'published' OR
           lexical_count<>NEW.expected_chunk_count OR NEW.ready_at IS NULL OR NEW.published_at IS NOT NULL THEN
            RAISE EXCEPTION 'vector build counts or source corpus state do not match the staged snapshot';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.state='ready' AND NEW.state IN ('published','failed') THEN
        IF NEW.state='published' THEN
            IF NEW.vector_count<>OLD.vector_count OR NEW.ready_at<>OLD.ready_at OR NEW.published_at IS NULL OR
               NOT EXISTS (SELECT 1 FROM keel_meta.retrieval_vector_heads h WHERE h.tenant_id=NEW.tenant_id
                 AND h.visibility_key=NEW.visibility_key AND h.model_id=NEW.model_id AND h.model_revision=NEW.model_revision
                 AND h.active_vector_build_id=NEW.vector_build_id) THEN
                RAISE EXCEPTION 'only the active validated vector build may be marked published';
            END IF;
            SELECT active_build_id,generation INTO active_corpus,active_corpus_generation FROM keel_meta.retrieval_corpus_heads
              WHERE tenant_id=NEW.tenant_id AND visibility_key=NEW.visibility_key;
            IF active_corpus<>NEW.corpus_build_id OR active_corpus_generation<>NEW.corpus_generation THEN
                RAISE EXCEPTION 'vector build corpus generation is no longer active';
            END IF;
            RETURN NEW;
        END IF;
        IF NEW.ready_at<>OLD.ready_at OR NEW.published_at IS NOT NULL THEN RAISE EXCEPTION 'failed ready vector timestamp shape invalid'; END IF;
        RETURN NEW;
    END IF;
    IF OLD.state='published' AND NEW.state='retired' THEN
        IF EXISTS (SELECT 1 FROM keel_meta.retrieval_vector_heads h WHERE h.tenant_id=OLD.tenant_id
          AND h.active_vector_build_id=OLD.vector_build_id) THEN RAISE EXCEPTION 'active vector build cannot be retired'; END IF;
        IF NEW.vector_count<>OLD.vector_count OR NEW.ready_at<>OLD.ready_at OR NEW.published_at<>OLD.published_at THEN
            RAISE EXCEPTION 'published vector build is immutable';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid retrieval vector build transition: % -> %',OLD.state,NEW.state;
END $$;

CREATE OR REPLACE FUNCTION keel_meta.guard_retrieval_vector_head()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE s text; corpus_id uuid; corpus_gen bigint; head_corpus uuid; head_generation bigint;
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.active_vector_build_id IS NOT NULL OR NEW.generation<>0 THEN RAISE EXCEPTION 'vector head must begin empty'; END IF;
        RETURN NEW;
    END IF;
    IF NEW.tenant_id<>OLD.tenant_id OR NEW.visibility_key<>OLD.visibility_key OR NEW.model_id<>OLD.model_id OR
       NEW.model_revision<>OLD.model_revision OR NEW.generation<>OLD.generation+1 OR NEW.active_vector_build_id IS NULL THEN
        RAISE EXCEPTION 'vector publication must advance one generation for the same tenant, cohort and model';
    END IF;
    SELECT state,corpus_build_id,corpus_generation INTO s,corpus_id,corpus_gen
      FROM keel_meta.retrieval_vector_builds WHERE tenant_id=NEW.tenant_id AND vector_build_id=NEW.active_vector_build_id FOR KEY SHARE;
    SELECT active_build_id,generation INTO head_corpus,head_generation FROM keel_meta.retrieval_corpus_heads
      WHERE tenant_id=NEW.tenant_id AND visibility_key=NEW.visibility_key FOR KEY SHARE;
    IF s<>'ready' OR corpus_id<>head_corpus OR corpus_gen<>head_generation THEN
        RAISE EXCEPTION 'only a ready vector build for the active corpus generation can be published';
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION keel_meta.provision_retrieval_hnsw_index(p_model_id text,p_model_revision text)
RETURNS name LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE dims integer; index_name name; existing name;
BEGIN
    SELECT dimensions,hnsw_index_name INTO dims,existing FROM keel_meta.retrieval_model_manifests
      WHERE model_id=p_model_id AND model_revision=p_model_revision;
    IF dims IS NULL THEN RAISE EXCEPTION 'unknown retrieval model manifest'; END IF;
    IF dims>4000 THEN RAISE EXCEPTION 'pgvector halfvec HNSW supports at most 4000 dimensions'; END IF;
    IF existing IS NOT NULL AND to_regclass('keel_meta.'||quote_ident(existing::text)) IS NOT NULL THEN RETURN existing; END IF;
    IF existing IS NOT NULL THEN
        index_name:=existing;
    ELSE
        index_name:=('retrieval_hnsw_'||substr(md5(p_model_id||':'||p_model_revision),1,32))::name;
    END IF;
    EXECUTE format('CREATE INDEX %I ON keel_meta.retrieval_vector_chunks USING hnsw ((embedding::public.halfvec(%s)) public.halfvec_cosine_ops) WHERE model_id=%L AND model_revision=%L',index_name,dims,p_model_id,p_model_revision);
    IF existing IS NULL THEN
        UPDATE keel_meta.retrieval_model_manifests SET hnsw_index_name=index_name
          WHERE model_id=p_model_id AND model_revision=p_model_revision;
    END IF;
    RETURN index_name;
END $$;

CREATE TRIGGER retrieval_vector_embedding_guard BEFORE INSERT OR UPDATE ON keel_meta.retrieval_vector_chunks
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_retrieval_vector_embedding();
CREATE TRIGGER retrieval_vector_staging_guard BEFORE INSERT OR UPDATE OR DELETE ON keel_meta.retrieval_vector_chunks
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_retrieval_vector_staged_row();
CREATE TRIGGER retrieval_vector_build_state_guard BEFORE INSERT OR UPDATE ON keel_meta.retrieval_vector_builds
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_retrieval_vector_build_state();
CREATE TRIGGER retrieval_vector_head_guard BEFORE INSERT OR UPDATE ON keel_meta.retrieval_vector_heads
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_retrieval_vector_head();
REVOKE ALL ON FUNCTION keel_meta.guard_retrieval_vector_embedding(),keel_meta.guard_retrieval_vector_staged_row(),
    keel_meta.guard_retrieval_vector_build_state(),keel_meta.guard_retrieval_vector_head(),
    keel_meta.provision_retrieval_hnsw_index(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.provision_retrieval_hnsw_index(text,text) TO keel_schema_owner;

ALTER TABLE keel_meta.retrieval_vector_builds ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.retrieval_vector_builds FORCE ROW LEVEL SECURITY;
CREATE POLICY retrieval_vector_builds_scope ON keel_meta.retrieval_vector_builds TO keel_app,keel_retrieval_indexer
    USING (tenant_id=(SELECT keel_private.current_tenant_id()) AND visibility_key=nullif(current_setting('keel.visibility_key',true),''))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()) AND visibility_key=nullif(current_setting('keel.visibility_key',true),''));
ALTER TABLE keel_meta.retrieval_vector_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.retrieval_vector_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY retrieval_vector_heads_scope ON keel_meta.retrieval_vector_heads TO keel_app,keel_retrieval_indexer
    USING (tenant_id=(SELECT keel_private.current_tenant_id()) AND visibility_key=nullif(current_setting('keel.visibility_key',true),''))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()) AND visibility_key=nullif(current_setting('keel.visibility_key',true),''));
ALTER TABLE keel_meta.retrieval_vector_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.retrieval_vector_chunks FORCE ROW LEVEL SECURITY;
CREATE POLICY retrieval_vector_chunks_scope ON keel_meta.retrieval_vector_chunks TO keel_app,keel_retrieval_indexer
    USING (tenant_id=(SELECT keel_private.current_tenant_id()) AND visibility_key=nullif(current_setting('keel.visibility_key',true),''))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()) AND visibility_key=nullif(current_setting('keel.visibility_key',true),''));

REVOKE ALL ON keel_meta.retrieval_model_manifests,keel_meta.retrieval_vector_builds,keel_meta.retrieval_vector_heads,
    keel_meta.retrieval_vector_chunks FROM PUBLIC,keel_app,keel_agent,keel_worker,keel_projector,keel_operator,keel_file_processor;
GRANT USAGE ON SCHEMA keel_meta,keel_private TO keel_retrieval_indexer;
GRANT EXECUTE ON FUNCTION keel_private.current_tenant_id() TO keel_retrieval_indexer;
GRANT SELECT ON keel_meta.retrieval_model_manifests,keel_meta.retrieval_vector_builds,keel_meta.retrieval_vector_heads,
    keel_meta.retrieval_vector_chunks TO keel_app;
GRANT SELECT ON keel_meta.retrieval_model_manifests TO keel_retrieval_indexer;
GRANT SELECT,INSERT ON keel_meta.retrieval_vector_builds,keel_meta.retrieval_vector_heads TO keel_retrieval_indexer;
GRANT UPDATE (state,vector_count,ready_at,published_at,updated_at) ON keel_meta.retrieval_vector_builds TO keel_retrieval_indexer;
GRANT UPDATE (active_vector_build_id,generation,updated_at) ON keel_meta.retrieval_vector_heads TO keel_retrieval_indexer;
GRANT SELECT,INSERT,DELETE ON keel_meta.retrieval_vector_chunks TO keel_retrieval_indexer;
