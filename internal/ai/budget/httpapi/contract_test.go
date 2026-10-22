package httpapi

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// repositoryRoot resolves the repository root so the handler can be checked against the
// published API contract.
func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve contract test source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "../../../.."))
}

func TestCostRoutesAreDocumentedInTheOpenAPIContract(t *testing.T) {
	loader := openapi3.NewLoader()
	api, err := loader.LoadFromFile(filepath.Join(repositoryRoot(t), "contracts", "openapi", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for path, operation := range map[string]string{
		"/v1/costs":                     "getCurrentCostBreakdown",
		"/v1/costs/{period_id}":         "getPeriodCostBreakdown",
		"/v1/costs/{period_id}/entries": "getCostEntries",
	} {
		item := api.Paths.Find(path)
		if item == nil {
			t.Fatalf("the API contract does not document %s", path)
		}
		if item.Get == nil {
			t.Fatalf("the API contract does not document a GET for %s", path)
		}
		if item.Get.OperationID != operation {
			t.Fatalf("the API contract operation for %s is %q, want %q", path, item.Get.OperationID, operation)
		}
	}
}
