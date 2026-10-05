// Package policy provides the offline, versioned policy and privacy boundary
// used to prepare future model calls. It has no provider implementation.
package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"regexp"
	"sort"
	"unicode/utf8"
)

var (
	ErrInvalidRegistry     = errors.New("AI policy registry is invalid")
	ErrPolicyRejected      = errors.New("AI invocation policy rejected the request")
	errProviderUnavailable = errors.New("AI provider is unavailable")
	errProviderFailed      = errors.New("AI provider invocation failed")
	errInvocationCanceled  = errors.New("AI invocation was canceled before provider dispatch")
)

const (
	maxPolicyInputBytes    = 64 * 1024
	maxOutputTokens        = 8192
	maxPromptTemplateBytes = 16 * 1024
	maxSegments            = 32

	ScrubberHighConfidenceV1 = "keel.scrubber.high-confidence.v1"
)

var (
	identifierPattern          = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)
	variablePattern            = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	templateVariablePattern    = regexp.MustCompile(`\{\{([a-z][a-z0-9_]*)\}\}`)
	strayTemplateMarkerPattern = regexp.MustCompile(`\{\{|\}\}`)
	emailPattern               = regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`)
	ssnPattern                 = regexp.MustCompile(`\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`)
	e164Pattern                = regexp.MustCompile(`\+[1-9][0-9]{7,14}\b`)
	bearerPattern              = regexp.MustCompile(`(?i)\bbearer\s+[A-Z0-9._~+/-]{8,}=?`)
	keyPattern                 = regexp.MustCompile(`(?i)\b(?:sk|pk|api|key)[_-](?:live[_-])?[A-Z0-9_-]{16,}\b`)
)

// These code-owned registrations deliberately contain no live provider and
// no executable tools. Add entries only with the matching adapter/capability
// review; unrecognized names cannot be frozen into a bundle.
var registeredProviderProfiles = map[string]map[string]map[string]struct{}{
	"offline-fake": {"v1": {"model-offline-v1": {}}},
}

var registeredToolCapabilities = map[string]struct{}{}

type PromptTemplate struct {
	ID        string
	Version   string
	Text      string
	Variables []string
}

type ProviderPolicy struct {
	ID      string
	Version string
	ModelID string
}

type GenerationLimits struct {
	MaxInputBytes   int
	MaxOutputTokens int
}

type ToolPolicy struct {
	Version string
	Allowed []string
}

type ScrubberPolicy struct {
	Version string
}

// Bundle is code-owned policy. Invocation requests may select an installed
// bundle but cannot supply or override any of its fields.
type Bundle struct {
	ID         string
	Version    string
	Prompt     PromptTemplate
	Provider   ProviderPolicy
	Generation GenerationLimits
	Tools      ToolPolicy
	Scrubber   ScrubberPolicy
}

type registryEntry struct {
	bundle Bundle
	digest string
}

type Registry struct {
	entries map[string]registryEntry
}

type PolicySnapshot struct {
	id                string
	version           string
	digest            string
	promptID          string
	promptVersion     string
	providerID        string
	providerVersion   string
	modelID           string
	toolPolicyVersion string
	scrubberVersion   string
	maxInputBytes     int
	maxOutputTokens   int
	allowedTools      []string
}

func (s PolicySnapshot) ID() string                { return s.id }
func (s PolicySnapshot) Version() string           { return s.version }
func (s PolicySnapshot) Digest() string            { return s.digest }
func (s PolicySnapshot) PromptID() string          { return s.promptID }
func (s PolicySnapshot) PromptVersion() string     { return s.promptVersion }
func (s PolicySnapshot) ProviderID() string        { return s.providerID }
func (s PolicySnapshot) ProviderVersion() string   { return s.providerVersion }
func (s PolicySnapshot) ModelID() string           { return s.modelID }
func (s PolicySnapshot) ToolPolicyVersion() string { return s.toolPolicyVersion }
func (s PolicySnapshot) ScrubberVersion() string   { return s.scrubberVersion }
func (s PolicySnapshot) MaxInputBytes() int        { return s.maxInputBytes }
func (s PolicySnapshot) MaxOutputTokens() int      { return s.maxOutputTokens }
func (s PolicySnapshot) AllowedTools() []string    { return append([]string(nil), s.allowedTools...) }
func (s PolicySnapshot) String() string {
	return fmt.Sprintf("[AI policy %s@%s %s]", s.id, s.version, s.digest)
}
func (s PolicySnapshot) GoString() string { return s.String() }

type Source string

const (
	SourceUser             Source = "user"
	SourceSupplierDocument Source = "supplier_document"
	SourceServerContext    Source = "server_context"
)

type Classification string

const (
	ClassificationGeneral      Classification = "general"
	ClassificationSensitive    Classification = "sensitive"
	ClassificationUnclassified Classification = "unclassified"
)

// InputSegment provenance and classification are server-supplied metadata.
// Request handlers must never accept these fields as client policy choices.
type InputSegment struct {
	Source         Source
	Classification Classification
	Text           string
}

type Request struct {
	BundleID      string
	BundleVersion string
	Variables     map[string]InputSegment
}

type SafePrompt struct {
	text string
}

func (p SafePrompt) String() string   { return "[AI prompt omitted]" }
func (p SafePrompt) GoString() string { return p.String() }

// ProviderText is the only API that exposes prepared prompt text. Callers must
// use it only to deliver an approved call to a configured provider.
func (p SafePrompt) ProviderText() string { return p.text }

type Call struct {
	prompt   SafePrompt
	snapshot PolicySnapshot
}

func (c Call) Prompt() SafePrompt     { return c.prompt }
func (c Call) Policy() PolicySnapshot { return cloneSnapshot(c.snapshot) }
func (c Call) ModelID() string        { return c.snapshot.modelID }
func (c Call) MaxOutputTokens() int   { return c.snapshot.maxOutputTokens }
func (c Call) AllowedTools() []string { return c.snapshot.AllowedTools() }
func (c Call) String() string         { return "[AI invocation omitted]" }
func (c Call) GoString() string       { return c.String() }

type provider interface {
	Complete(context.Context, Call) (string, error)
}

// NewRegistry validates and freezes code-owned bundles. All slice-backed
// policy values are copied and normalized before storage.
func NewRegistry(bundles []Bundle) (*Registry, error) {
	if len(bundles) == 0 {
		return nil, ErrInvalidRegistry
	}
	registry := &Registry{entries: make(map[string]registryEntry, len(bundles))}
	for _, input := range bundles {
		bundle := cloneBundle(input)
		if err := validateBundle(bundle); err != nil {
			return nil, fmt.Errorf("%w: bundle validation failed", ErrInvalidRegistry)
		}
		sort.Strings(bundle.Prompt.Variables)
		sort.Strings(bundle.Tools.Allowed)
		key := registryKey(bundle.ID, bundle.Version)
		if _, exists := registry.entries[key]; exists {
			return nil, ErrInvalidRegistry
		}
		digest, err := bundleDigest(bundle)
		if err != nil {
			return nil, ErrInvalidRegistry
		}
		registry.entries[key] = registryEntry{bundle: bundle, digest: digest}
	}
	return registry, nil
}

// Prepare validates the exact bundle reference, scrubs every variable, and
// returns a provider-ready call. It performs no network, persistence, or log
// writes; a future runtime must apply K4.3/K4.4 admission before execution.
func (r *Registry) Prepare(request Request) (Call, error) {
	if r == nil || r.entries == nil || !validIdentifier(request.BundleID) || !validVersion(request.BundleVersion) {
		return Call{}, ErrPolicyRejected
	}
	entry, ok := r.entries[registryKey(request.BundleID, request.BundleVersion)]
	if !ok {
		return Call{}, ErrPolicyRejected
	}
	bundle := entry.bundle
	if len(request.Variables) != len(bundle.Prompt.Variables) {
		return Call{}, ErrPolicyRejected
	}
	prepared := make(map[string]string, len(bundle.Prompt.Variables))
	inputBytes := 0
	for _, name := range bundle.Prompt.Variables {
		segment, exists := request.Variables[name]
		if !exists || !validSource(segment.Source) || segment.Classification != ClassificationGeneral || !utf8Valid(segment.Text) {
			return Call{}, ErrPolicyRejected
		}
		if len(segment.Text) > bundle.Generation.MaxInputBytes-inputBytes {
			return Call{}, ErrPolicyRejected
		}
		inputBytes += len(segment.Text)
		prepared[name] = scrubText(segment.Text)
	}
	for name := range request.Variables {
		if !contains(bundle.Prompt.Variables, name) {
			return Call{}, ErrPolicyRejected
		}
	}
	prompt := bundle.Prompt.Text
	prompt = templateVariablePattern.ReplaceAllStringFunc(prompt, func(marker string) string {
		match := templateVariablePattern.FindStringSubmatch(marker)
		return prepared[match[1]]
	})
	// Re-scan the fully expanded prompt because trusted template fragments and
	// individually clean variables can join into a recognized sensitive value.
	prompt = scrubText(prompt)
	if len(prompt) > bundle.Generation.MaxInputBytes || !utf8Valid(prompt) {
		return Call{}, ErrPolicyRejected
	}
	snapshot := snapshotFor(bundle, entry.digest)
	return Call{prompt: SafePrompt{text: prompt}, snapshot: snapshot}, nil
}

// execute is a package-private provider seam used by contract tests. It exposes
// only a prepared SafePrompt, emits content-free outcomes, and discards provider
// error details. Production gateway wiring remains behind K4.1/K4.3/K4.4 gates.
func (r *Registry) execute(ctx context.Context, request Request, provider provider, logger *slog.Logger) (string, error) {
	if ctx == nil {
		return "", ErrPolicyRejected
	}
	call, err := r.Prepare(request)
	if err != nil {
		if logger != nil {
			logger.WarnContext(ctx, "AI request rejected", "component", "ai_policy", "operation", "prepare", "result", "rejected", "errorcode", "policy_rejected")
		}
		return "", ErrPolicyRejected
	}
	if provider == nil || isNilProvider(provider) {
		return "", errProviderUnavailable
	}
	if ctx.Err() != nil {
		return "", errInvocationCanceled
	}
	if logger != nil {
		logger.InfoContext(ctx, "AI request prepared", "component", "ai_policy", "operation", "invoke", "policyversion", call.snapshot.version, "result", "prepared")
	}
	response, err := provider.Complete(ctx, call)
	if err != nil {
		if logger != nil {
			logger.WarnContext(ctx, "AI provider failed", "component", "ai_policy", "operation", "invoke", "policyversion", call.snapshot.version, "result", "failed", "errorcode", "provider_failed")
		}
		return "", errProviderFailed
	}
	if logger != nil {
		logger.InfoContext(ctx, "AI request completed", "component", "ai_policy", "operation", "invoke", "policyversion", call.snapshot.version, "result", "complete")
	}
	return response, nil
}

func validateBundle(b Bundle) error {
	if !validIdentifier(b.ID) || !validVersion(b.Version) ||
		!validIdentifier(b.Prompt.ID) || !validVersion(b.Prompt.Version) || len(b.Prompt.Text) == 0 || len(b.Prompt.Text) > maxPromptTemplateBytes ||
		!registeredProviderModel(b.Provider.ID, b.Provider.Version, b.Provider.ModelID) ||
		b.Generation.MaxInputBytes < 1 || b.Generation.MaxInputBytes > maxPolicyInputBytes || b.Generation.MaxOutputTokens < 1 || b.Generation.MaxOutputTokens > maxOutputTokens ||
		b.Tools.Version != "tools.none.v1" || len(b.Prompt.Variables) == 0 || len(b.Prompt.Variables) > maxSegments ||
		!validVersion(b.Scrubber.Version) || b.Scrubber.Version != ScrubberHighConfidenceV1 {
		return ErrInvalidRegistry
	}
	if scrubText(b.Prompt.Text) != b.Prompt.Text {
		return ErrInvalidRegistry
	}
	variables := make(map[string]struct{}, len(b.Prompt.Variables))
	for _, variable := range b.Prompt.Variables {
		if !variablePattern.MatchString(variable) {
			return ErrInvalidRegistry
		}
		if _, exists := variables[variable]; exists {
			return ErrInvalidRegistry
		}
		variables[variable] = struct{}{}
	}
	seenTools := make(map[string]struct{}, len(b.Tools.Allowed))
	for _, tool := range b.Tools.Allowed {
		if !validIdentifier(tool) {
			return ErrInvalidRegistry
		}
		if _, registered := registeredToolCapabilities[tool]; !registered {
			return ErrInvalidRegistry
		}
		if _, exists := seenTools[tool]; exists {
			return ErrInvalidRegistry
		}
		seenTools[tool] = struct{}{}
	}
	matches := templateVariablePattern.FindAllStringSubmatch(b.Prompt.Text, -1)
	if len(matches) == 0 {
		return ErrInvalidRegistry
	}
	withoutVariables := templateVariablePattern.ReplaceAllString(b.Prompt.Text, "")
	if strayTemplateMarkerPattern.MatchString(withoutVariables) {
		return ErrInvalidRegistry
	}
	seenVariables := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		name := match[1]
		if _, exists := variables[name]; !exists {
			return ErrInvalidRegistry
		}
		seenVariables[name] = struct{}{}
	}
	if len(seenVariables) != len(variables) {
		return ErrInvalidRegistry
	}
	return nil
}

func bundleDigest(bundle Bundle) (string, error) {
	canonical := struct {
		ID         string           `json:"id"`
		Version    string           `json:"version"`
		Prompt     PromptTemplate   `json:"prompt"`
		Provider   ProviderPolicy   `json:"provider"`
		Generation GenerationLimits `json:"generation"`
		Tools      ToolPolicy       `json:"tools"`
		Scrubber   ScrubberPolicy   `json:"scrubber"`
	}{bundle.ID, bundle.Version, bundle.Prompt, bundle.Provider, bundle.Generation, bundle.Tools, bundle.Scrubber}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func snapshotFor(bundle Bundle, digest string) PolicySnapshot {
	return PolicySnapshot{
		id: bundle.ID, version: bundle.Version, digest: digest,
		promptID: bundle.Prompt.ID, promptVersion: bundle.Prompt.Version,
		providerID: bundle.Provider.ID, providerVersion: bundle.Provider.Version, modelID: bundle.Provider.ModelID,
		toolPolicyVersion: bundle.Tools.Version, scrubberVersion: bundle.Scrubber.Version,
		maxInputBytes: bundle.Generation.MaxInputBytes, maxOutputTokens: bundle.Generation.MaxOutputTokens,
		allowedTools: append([]string(nil), bundle.Tools.Allowed...),
	}
}

func cloneSnapshot(snapshot PolicySnapshot) PolicySnapshot {
	snapshot.allowedTools = append([]string(nil), snapshot.allowedTools...)
	return snapshot
}

func cloneBundle(bundle Bundle) Bundle {
	bundle.Prompt.Variables = append([]string(nil), bundle.Prompt.Variables...)
	bundle.Tools.Allowed = append([]string(nil), bundle.Tools.Allowed...)
	return bundle
}

func scrubText(input string) string {
	text := input
	text = bearerPattern.ReplaceAllString(text, "[REDACTED_CREDENTIAL]")
	text = keyPattern.ReplaceAllString(text, "[REDACTED_CREDENTIAL]")
	text = ssnPattern.ReplaceAllString(text, "[REDACTED_SSN]")
	text = emailPattern.ReplaceAllString(text, "[REDACTED_EMAIL]")
	text = e164Pattern.ReplaceAllString(text, "[REDACTED_PHONE]")
	return text
}

func registryKey(id, version string) string { return id + "\x00" + version }

func validIdentifier(value string) bool { return identifierPattern.MatchString(value) }

func validVersion(value string) bool { return len(value) <= 64 && validIdentifier(value) }

func validSource(source Source) bool {
	return source == SourceUser || source == SourceSupplierDocument || source == SourceServerContext
}

func registeredProviderModel(providerID, version, modelID string) bool {
	versions, ok := registeredProviderProfiles[providerID]
	if !ok {
		return false
	}
	models, ok := versions[version]
	if !ok {
		return false
	}
	_, ok = models[modelID]
	return ok
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func isNilProvider(provider provider) bool {
	value := reflect.ValueOf(provider)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func utf8Valid(value string) bool { return utf8.ValidString(value) }
