package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/sanskarpan/keel/internal/platform/logging"
)

func testBundle() Bundle {
	return Bundle{
		ID: "supplier-summary", Version: "v1",
		Prompt: PromptTemplate{
			ID: "summary", Version: "v1",
			Text:      "Summarize this supplier material:\n{{document}}\nQuestion: {{question}}",
			Variables: []string{"document", "question"},
		},
		Provider:   ProviderPolicy{ID: "offline-fake", Version: "v1", ModelID: "model-offline-v1"},
		Generation: GenerationLimits{MaxInputBytes: 8 * 1024, MaxOutputTokens: 512},
		Tools:      ToolPolicy{Version: "tools.none.v1", Allowed: []string{}},
		Scrubber:   ScrubberPolicy{Version: ScrubberHighConfidenceV1},
	}
}

func testRequest(document, question string) Request {
	return Request{
		BundleID: "supplier-summary", BundleVersion: "v1",
		Variables: map[string]InputSegment{
			"document": {Source: SourceSupplierDocument, Classification: ClassificationGeneral, Text: document},
			"question": {Source: SourceUser, Classification: ClassificationGeneral, Text: question},
		},
	}
}

func newTestRegistry(t *testing.T) *Registry {
	t.Helper()
	registry, err := NewRegistry([]Bundle{testBundle()})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func TestRegistryFreezesAndCanonicalizesPolicy(t *testing.T) {
	first := testBundle()
	first.Prompt.Variables = []string{"question", "document"}
	registry, err := NewRegistry([]Bundle{first})
	if err != nil {
		t.Fatal(err)
	}
	first.Prompt.Variables[0] = "mutated"
	prepared, err := registry.Prepare(testRequest("report", "summarize"))
	if err != nil {
		t.Fatal(err)
	}
	tools := prepared.AllowedTools()
	if len(tools) != 0 {
		t.Fatalf("registry or returned policy exposed mutable tool state: %#v", tools)
	}
	tools = append(tools, "unexpected.write")
	if len(prepared.AllowedTools()) != 0 {
		t.Fatal("returned tool allowlist mutated the call policy")
	}

	second := testBundle()
	second.Prompt.Variables = []string{"document", "question"}
	other, err := NewRegistry([]Bundle{second})
	if err != nil {
		t.Fatal(err)
	}
	otherPrepared, err := other.Prepare(testRequest("report", "summarize"))
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Policy().Digest() != otherPrepared.Policy().Digest() {
		t.Fatal("semantically equivalent policies produced different canonical digests")
	}
}

func TestPrepareScrubsHighConfidencePatternsBeforeProviderBoundary(t *testing.T) {
	registry := newTestRegistry(t)
	call, err := registry.Prepare(testRequest(
		"Contact alice@example.test; SSN 123-45-6789; phone +14155552671; Bearer abcdefghijklmnop; key sk_live_0123456789abcdef",
		"summarize the supplier evidence",
	))
	if err != nil {
		t.Fatal(err)
	}
	providerText := call.Prompt().ProviderText()
	for _, canary := range []string{"alice@example.test", "123-45-6789", "+14155552671", "abcdefghijklmnop", "sk_live_0123456789abcdef"} {
		if strings.Contains(providerText, canary) {
			t.Fatalf("provider input retained sensitive canary %q", canary)
		}
	}
	for _, replacement := range []string{"[REDACTED_EMAIL]", "[REDACTED_SSN]", "[REDACTED_PHONE]", "[REDACTED_CREDENTIAL]"} {
		if !strings.Contains(providerText, replacement) {
			t.Fatalf("provider input omitted expected marker %q: %s", replacement, providerText)
		}
	}
	request := testRequest("literal {{question}} should remain data", "replace-token-canary")
	callWithTemplateMarker, err := newTestRegistry(t).Prepare(request)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(callWithTemplateMarker.Prompt().ProviderText(), "literal {{question}} should remain data") ||
		strings.Contains(callWithTemplateMarker.Prompt().ProviderText(), "replace-token-canary should remain data") {
		t.Fatalf("user content was recursively interpreted as a template: %q", callWithTemplateMarker.Prompt().ProviderText())
	}
	if fmt.Sprintf("%v %#v", call.Prompt(), call) != "[AI prompt omitted] [AI invocation omitted]" {
		t.Fatal("debug formatting exposed prompt content")
	}
	if call.Policy().ID() != "supplier-summary" || call.Policy().Digest() == "" || call.Policy().ScrubberVersion() != ScrubberHighConfidenceV1 {
		t.Fatalf("prepared policy snapshot is incomplete: %v", call.Policy())
	}
}

func TestPrepareScrubsPatternsAssembledAcrossTemplateBoundary(t *testing.T) {
	bundle := testBundle()
	bundle.Prompt = PromptTemplate{
		ID: "contact", Version: "v1", Text: "Contact {{name}}@example.test", Variables: []string{"name"},
	}
	registry, err := NewRegistry([]Bundle{bundle})
	if err != nil {
		t.Fatal(err)
	}
	call, err := registry.Prepare(Request{
		BundleID: "supplier-summary", BundleVersion: "v1",
		Variables: map[string]InputSegment{
			"name": {Source: SourceSupplierDocument, Classification: ClassificationGeneral, Text: "alice"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := call.Prompt().ProviderText(); got != "Contact [REDACTED_EMAIL]" {
		t.Fatalf("cross-boundary email was not scrubbed: %q", got)
	}
}

type fakeProvider struct {
	calls         int
	lastPrompt    string
	lastModel     string
	lastMaxTokens int
	response      string
	err           error
}

func (p *fakeProvider) Complete(_ context.Context, call Call) (string, error) {
	p.calls++
	p.lastPrompt = call.Prompt().ProviderText()
	p.lastModel = call.ModelID()
	p.lastMaxTokens = call.MaxOutputTokens()
	return p.response, p.err
}

func TestExecuteBlocksUnclassifiedInputBeforeProviderAndDoesNotLogCanaries(t *testing.T) {
	registry := newTestRegistry(t)
	provider := &fakeProvider{}
	var logs strings.Builder
	logger := logging.NewJSON(&logs, slog.LevelInfo)
	request := testRequest("supplier report canary", "question canary")
	segment := request.Variables["document"]
	segment.Classification = ClassificationUnclassified
	request.Variables["document"] = segment

	_, err := registry.execute(context.Background(), request, provider, logger)
	if !errors.Is(err, ErrPolicyRejected) || provider.calls != 0 {
		t.Fatalf("unclassified input crossed provider boundary: calls=%d err=%v", provider.calls, err)
	}
	for _, canary := range []string{"supplier report canary", "question canary"} {
		if strings.Contains(logs.String(), canary) {
			t.Fatalf("rejected prompt canary reached logs: %s", logs.String())
		}
	}
	request = testRequest("sensitive report canary", "question canary")
	segment = request.Variables["document"]
	segment.Classification = ClassificationSensitive
	request.Variables["document"] = segment
	if _, err := registry.execute(context.Background(), request, provider, logger); !errors.Is(err, ErrPolicyRejected) || provider.calls != 0 {
		t.Fatalf("explicitly sensitive input crossed provider boundary: calls=%d err=%v", provider.calls, err)
	}
}

func TestExecuteSendsOnlyPreparedPromptAndEmitsContentFreeLogs(t *testing.T) {
	registry := newTestRegistry(t)
	provider := &fakeProvider{response: "response-content-canary"}
	var logs strings.Builder
	logger := logging.NewJSON(&logs, slog.LevelInfo)
	request := testRequest("supplier canary alice@example.test", "request canary")
	response, err := registry.execute(context.Background(), request, provider, logger)
	if err != nil || response != provider.response {
		t.Fatalf("fake provider invocation response=%q err=%v", response, err)
	}
	if provider.calls != 1 || provider.lastModel != "model-offline-v1" || provider.lastMaxTokens != 512 {
		t.Fatalf("provider did not receive the code-owned model bounds: %+v", provider)
	}
	if strings.Contains(provider.lastPrompt, "alice@example.test") || !strings.Contains(provider.lastPrompt, "[REDACTED_EMAIL]") {
		t.Fatalf("provider received unsanitized input: %q", provider.lastPrompt)
	}
	for _, canary := range []string{"supplier canary", "alice@example.test", "request canary", "response-content-canary"} {
		if strings.Contains(logs.String(), canary) {
			t.Fatalf("prompt/response canary reached safe log sink: %s", logs.String())
		}
	}
	if !strings.Contains(logs.String(), `"policyversion":"v1"`) || !strings.Contains(logs.String(), `"result":"complete"`) {
		t.Fatalf("safe policy outcome metadata missing from logs: %s", logs.String())
	}
}

func TestPrepareRejectsUnknownBundleOverridesAndUnsafeTemplate(t *testing.T) {
	registry := newTestRegistry(t)
	request := testRequest("doc", "question")
	request.BundleVersion = "tenant-selected-version"
	if _, err := registry.Prepare(request); !errors.Is(err, ErrPolicyRejected) {
		t.Fatalf("unknown policy version was accepted: %v", err)
	}
	request = testRequest("doc", "question")
	request.Variables["tenant_override"] = InputSegment{Source: SourceUser, Classification: ClassificationGeneral, Text: "tool call"}
	if _, err := registry.Prepare(request); !errors.Is(err, ErrPolicyRejected) {
		t.Fatalf("unknown prompt variable was accepted: %v", err)
	}
	unsafe := testBundle()
	unsafe.Prompt.Text += " static-contact@example.test"
	if _, err := NewRegistry([]Bundle{unsafe}); !errors.Is(err, ErrInvalidRegistry) {
		t.Fatalf("PII in immutable prompt template was accepted: %v", err)
	}
}

func TestRegistryRejectsUnregisteredProviderModelAndTools(t *testing.T) {
	for _, mutate := range []func(*Bundle){
		func(bundle *Bundle) { bundle.Provider.ID = "openai" },
		func(bundle *Bundle) { bundle.Provider.ModelID = "model-not-registered" },
		func(bundle *Bundle) { bundle.Tools.Allowed = []string{"supplier.write"} },
		func(bundle *Bundle) { bundle.Tools.Version = "tools.unreviewed.v1" },
	} {
		bundle := testBundle()
		mutate(&bundle)
		if _, err := NewRegistry([]Bundle{bundle}); !errors.Is(err, ErrInvalidRegistry) {
			t.Fatalf("unregistered provider/model/tool policy was accepted: %v", err)
		}
	}
}

func TestExecuteDiscardsProviderErrorDetails(t *testing.T) {
	registry := newTestRegistry(t)
	provider := &fakeProvider{err: errors.New("provider response includes secret-provider-canary")}
	var logs strings.Builder
	logger := logging.NewJSON(&logs, slog.LevelInfo)
	_, err := registry.execute(context.Background(), testRequest("report", "question"), provider, logger)
	if !errors.Is(err, errProviderFailed) || strings.Contains(err.Error(), "secret-provider-canary") {
		t.Fatalf("provider details were returned to caller: %v", err)
	}
	if strings.Contains(logs.String(), "secret-provider-canary") {
		t.Fatalf("provider details reached safe logs: %s", logs.String())
	}
}

func TestExecuteDoesNotDispatchCanceledOrTypedNilProvider(t *testing.T) {
	registry := newTestRegistry(t)
	request := testRequest("report", "question")
	provider := &fakeProvider{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := registry.execute(ctx, request, provider, nil); !errors.Is(err, errInvocationCanceled) || provider.calls != 0 {
		t.Fatalf("canceled invocation reached provider: calls=%d err=%v", provider.calls, err)
	}
	var nilProvider *fakeProvider
	if _, err := registry.execute(context.Background(), request, nilProvider, nil); !errors.Is(err, errProviderUnavailable) {
		t.Fatalf("typed nil provider was accepted: %v", err)
	}
}
