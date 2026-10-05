package contracts_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve contract test source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "../.."))
}

func readFixture(t *testing.T, root, relativePath string) []byte {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relativePath))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", relativePath, err)
	}
	return data
}

func compileSchema(t *testing.T, path string) *jsonschema.Schema {
	t.Helper()
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	location := (&url.URL{Scheme: "file", Path: filepath.ToSlash(absolutePath)}).String()
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	schema, err := compiler.Compile(location)
	if err != nil {
		t.Fatalf("compile JSON Schema %s: %v", path, err)
	}
	return schema
}

func decodeFixture(t *testing.T, path string, data []byte) any {
	t.Helper()
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("decode JSON fixture %s: %v", path, err)
	}
	return value
}

func TestOpenAPIContractLoadsAndValidates(t *testing.T) {
	root := repositoryRoot(t)
	path := filepath.Join(root, "contracts/openapi/openapi.yaml")
	loader := openapi3.NewLoader()
	loader.Context = context.Background()
	loader.IsExternalRefsAllowed = true
	api, err := loader.LoadFromFile(path)
	if err != nil {
		t.Fatalf("load OpenAPI contract: %v", err)
	}
	if err := api.Validate(context.Background()); err != nil {
		t.Fatalf("validate OpenAPI contract: %v", err)
	}
	for _, requiredPath := range []string{
		"/health/live", "/health/ready", "/health/startup", "/version",
		"/v1/orders", "/v1/orders/{order_id}/submit", "/v1/orders/{order_id}/events",
		"/v1/supplier-invitations",
		"/v1/supplier-review-policies",
		"/v1/supplier-cases",
		"/v1/supplier-cases/{case_id}",
		"/v1/supplier-cases/{case_id}/evidence",
		"/v1/supplier-cases/{case_id}/submit",
		"/v1/public/tenants/{tenant_id}/supplier-invitations/accept",
		"/v1/public/tenants/{tenant_id}/supplier-upload-sessions/uploads",
		"/v1/public/tenants/{tenant_id}/supplier-uploads/{upload_id}/content",
		"/v1/public/tenants/{tenant_id}/supplier-uploads/{upload_id}/capability",
		"/v1/public/tenants/{tenant_id}/supplier-uploads/{upload_id}",
	} {
		if _, ok := api.Paths.Map()[requiredPath]; !ok {
			t.Errorf("OpenAPI contract is missing %s", requiredPath)
		}
	}
}

func TestOrderQuantityContractIsPositiveAndBounded(t *testing.T) {
	root := repositoryRoot(t)
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	api, err := loader.LoadFromFile(filepath.Join(root, "contracts/openapi/openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	request := api.Components.Schemas["CreateOrderRequest"].Value
	quantity := request.Properties["line_items"].Value.Items.Value.Properties["quantity"].Value
	for _, value := range []string{"1", "0.000001", "12.34"} {
		if err := quantity.VisitJSON(value, openapi3.EnableJSONSchema2020()); err != nil {
			t.Errorf("valid quantity %q rejected: %v", value, err)
		}
	}
	for _, value := range []string{"0", "0.0", "0.000000", "-1", "1e2", "922337203685477580712345678901234567890"} {
		if err := quantity.VisitJSON(value, openapi3.EnableJSONSchema2020()); err == nil {
			t.Errorf("invalid quantity %q accepted", value)
		}
	}
}

func TestDeploymentRecipeFixtures(t *testing.T) {
	root := repositoryRoot(t)
	schema := compileSchema(t, filepath.Join(root, "contracts/deployment-recipe.schema.json"))
	fixtures := []struct {
		path  string
		valid bool
	}{
		{"contracts/fixtures/deployment-recipe/keel-preview.example.json", true},
		{"contracts/fixtures/deployment-recipe/keel-preview.invalid.json", false},
	}
	for _, fixture := range fixtures {
		t.Run(filepath.Base(fixture.path), func(t *testing.T) {
			data := readFixture(t, root, fixture.path)
			err := schema.Validate(decodeFixture(t, fixture.path, data))
			if fixture.valid {
				var recipe struct {
					EventSchemaBundle string `json:"event_schema_bundle"`
				}
				if err := json.Unmarshal(data, &recipe); err != nil {
					t.Fatal(err)
				}
				eventSchema := readFixture(t, root, "contracts/events/order-submitted.v1.schema.json")
				digest := sha256.Sum256(eventSchema)
				if got, want := recipe.EventSchemaBundle, "sha256:"+hex.EncodeToString(digest[:]); got != want {
					t.Errorf("event_schema_bundle = %q, want digest of canonical event schema %q", got, want)
				}
			}
			if fixture.valid && err != nil {
				t.Fatalf("expected valid recipe fixture: %v", err)
			}
			if !fixture.valid && err == nil {
				t.Fatal("invalid recipe fixture unexpectedly passed")
			}
		})
	}
}

func TestRetrievalEvaluationSchemasAndSeedCorpus(t *testing.T) {
	root := repositoryRoot(t)
	corpusSchema := compileSchema(t, filepath.Join(root, "research/retrieval/v1/corpus.schema.json"))
	manifestSchema := compileSchema(t, filepath.Join(root, "research/retrieval/v1/build-manifest.schema.json"))
	corpus := readFixture(t, root, "research/retrieval/v1/corpus.json")
	manifest := readFixture(t, root, "research/retrieval/v1/build-manifest.json")
	if err := corpusSchema.Validate(decodeFixture(t, "retrieval corpus", corpus)); err != nil {
		t.Fatalf("retrieval corpus does not match schema: %v", err)
	}
	if err := manifestSchema.Validate(decodeFixture(t, "retrieval build manifest", manifest)); err != nil {
		t.Fatalf("retrieval build manifest does not match schema: %v", err)
	}
}

func TestOrderEventFixtures(t *testing.T) {
	root := repositoryRoot(t)
	schema := compileSchema(t, filepath.Join(root, "contracts/events/order-submitted.v1.schema.json"))
	fixtures := []struct {
		path  string
		valid bool
	}{
		{"contracts/fixtures/events/order-submitted.v1.json", true},
		{"contracts/fixtures/events/order-submitted.v1.invalid.json", false},
	}
	for _, fixture := range fixtures {
		t.Run(filepath.Base(fixture.path), func(t *testing.T) {
			data := readFixture(t, root, fixture.path)
			err := schema.Validate(decodeFixture(t, fixture.path, data))
			if fixture.valid && err != nil {
				t.Fatalf("expected valid event fixture: %v", err)
			}
			if !fixture.valid && err == nil {
				t.Fatal("invalid event fixture unexpectedly passed")
			}
		})
	}
}

func TestContractJSONFixturesAreStrictJSON(t *testing.T) {
	root := repositoryRoot(t)
	fixtures := []string{
		"contracts/fixtures/deployment-recipe/keel-preview.example.json",
		"contracts/fixtures/deployment-recipe/keel-preview.invalid.json",
		"contracts/fixtures/events/order-submitted.v1.json",
		"contracts/fixtures/events/order-submitted.v1.invalid.json",
	}
	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			var value any
			if err := json.Unmarshal(readFixture(t, root, fixture), &value); err != nil {
				t.Fatal(fmt.Errorf("invalid JSON: %w", err))
			}
		})
	}
}
