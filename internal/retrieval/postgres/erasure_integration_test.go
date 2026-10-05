package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/retrieval/index"
)

func TestPostgreSQLLexicalPublicationRejectsPreStagedWithdrawnSource(t *testing.T) {
	appDB, indexerDB := retrievalTestDBs(t)
	app, _ := New(appDB)
	indexer, _ := New(indexerDB)
	ctx := context.Background()
	tenant := tenancy.TenantID(uuid.NewString())
	visibility := "withdraw-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	hasher, err := index.NewHMACTermHasher(string(tenant), "withdrawal-key-v1", []byte(strings.Repeat("w", 32)))
	if err != nil {
		t.Fatal(err)
	}
	buildID := uuid.New()
	chunk := preparedChunk(t, hasher, uuid.New(), "pre-staged withdrawn source")
	if err := indexer.BeginBuild(ctx, tenant, visibility, buildSpec(buildID, hasher.KeyID(), 1)); err != nil {
		t.Fatal(err)
	}
	if err := indexer.StageBatch(ctx, tenant, visibility, buildID, []index.Chunk{chunk}); err != nil {
		t.Fatal(err)
	}
	if _, err := indexer.Finalize(ctx, tenant, visibility, buildID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.WithdrawSource(ctx, tenant, visibility, uuid.New(), chunk.DocumentVersionID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, err := indexer.Publish(ctx, tenant, visibility, buildID, 0); err == nil {
		t.Fatal("lexical build published after its source was withdrawn")
	}
	if _, err := app.ActiveBuild(ctx, tenant, visibility); !errors.Is(err, ErrNoActiveBuild) {
		t.Fatalf("withdrawn build became active: %v", err)
	}
}

func TestPostgreSQLVectorPublicationRejectsWithdrawnSource(t *testing.T) {
	appDB, indexerDB, adminDB := retrievalTestDBsWithAdmin(t)
	app, _ := New(appDB)
	indexer, _ := New(indexerDB)
	ctx := context.Background()
	manifest := vectorFixtureManifest(t)
	registerVectorTestModel(t, adminDB, manifest)
	tenant := tenancy.TenantID(uuid.NewString())
	visibility := "vector-withdraw-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	_, chunks := createVectorSourceCorpus(t, indexer, tenant, visibility, []string{"vector source staged before withdrawal"})
	build, err := indexer.BeginVectorBuild(ctx, tenant, visibility, VectorBuildSpec{ID: uuid.New(), Model: manifest})
	if err != nil {
		t.Fatal(err)
	}
	if err := indexer.StageVectorBatch(ctx, tenant, visibility, build.ID, []VectorChunk{{ChunkID: chunks[0].ID, ModelInputTokens: 5, Values: []float32{1, 0, 0}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := indexer.FinalizeVectorBuild(ctx, tenant, visibility, build.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.WithdrawSource(ctx, tenant, visibility, uuid.New(), chunks[0].DocumentVersionID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, err := indexer.PublishVectorBuild(ctx, tenant, visibility, build.ID, 0); err == nil {
		t.Fatal("vector build published after its source was withdrawn")
	}
	if _, err := app.ActiveVectorBuild(ctx, tenant, visibility, manifest.ID, manifest.Revision); !errors.Is(err, ErrNoActiveVectorBuild) {
		t.Fatalf("withdrawn vectors became active: %v", err)
	}
}
