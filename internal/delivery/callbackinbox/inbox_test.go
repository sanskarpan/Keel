package callbackinbox

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

type verifierFunc func(context.Context, VerificationRequest) (VerifiedEvent, error)

func (f verifierFunc) Verify(ctx context.Context, request VerificationRequest) (VerifiedEvent, error) {
	return f(ctx, request)
}

func validRequest() VerificationRequest {
	return VerificationRequest{
		Provider:        "provider_one",
		ProviderEventID: "evt_abc123",
		Payload:         []byte(`{"status":"paid"}`),
		Signature:       []byte("signature"),
		Timestamp:       "2026-01-01T00:00:00Z",
	}
}

func validEvent() VerifiedEvent {
	tenant, _ := tenancy.ParseTenantID("11111111-1111-4111-8111-111111111111")
	return VerifiedEvent{
		Tenant:          tenant,
		Provider:        "provider_one",
		ProviderEventID: "evt_abc123",
		PayloadDigest:   DigestPayload([]byte(`{"status":"paid"}`)),
		EventType:       "payment.settled",
		KeyID:           "key_2026_01",
		OccurredAt:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// lazyDB returns a pool that is never connected, so tests can exercise the pre-database contract.
func lazyDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", "postgres://127.0.0.1:1/keel_unused?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestDigestPayloadIsCanonicalSHA256(t *testing.T) {
	const abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := DigestPayload([]byte("abc")); got != abc {
		t.Fatalf("digest was %q, want %q", got, abc)
	}
	if DigestPayload([]byte("abc")) != DigestPayload([]byte("abc")) {
		t.Fatal("digest is not stable for identical payloads")
	}
	if DigestPayload([]byte("abc")) == DigestPayload([]byte("abd")) {
		t.Fatal("digest collided for distinct payloads")
	}
}

func TestNewRequiresDatabaseAndVerifier(t *testing.T) {
	if _, err := New(nil, verifierFunc(func(context.Context, VerificationRequest) (VerifiedEvent, error) {
		return VerifiedEvent{}, nil
	})); err == nil {
		t.Fatal("expected an error for a missing database")
	}
	if _, err := New(lazyDB(t), nil); err == nil {
		t.Fatal("expected an error for a missing verifier")
	}
}

func TestValidateRequestRejectsUnboundedInput(t *testing.T) {
	cases := map[string]func(*VerificationRequest){
		"missing provider":   func(r *VerificationRequest) { r.Provider = "" },
		"uppercase provider": func(r *VerificationRequest) { r.Provider = "Provider" },
		"short provider":     func(r *VerificationRequest) { r.Provider = "p" },
		"missing event id":   func(r *VerificationRequest) { r.ProviderEventID = "" },
		"unbounded event id": func(r *VerificationRequest) { r.ProviderEventID = strings.Repeat("a", 129) },
		"empty payload":      func(r *VerificationRequest) { r.Payload = nil },
		"unbounded payload":  func(r *VerificationRequest) { r.Payload = make([]byte, MaxPayloadBytes+1) },
		"unsupported char":   func(r *VerificationRequest) { r.ProviderEventID = "evt abc" },
	}
	for name, mutate := range cases {
		request := validRequest()
		mutate(&request)
		if err := validateRequest(request); !errors.Is(err, ErrInvalidCallback) {
			t.Fatalf("%s: error was %v, want ErrInvalidCallback", name, err)
		}
	}
	request := validRequest()
	request.Signature = nil
	if err := validateRequest(request); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("missing signature error was %v, want ErrUnauthenticated", err)
	}
}

func TestValidateEventRejectsUntrustedClaims(t *testing.T) {
	cases := map[string]func(*VerifiedEvent){
		"provider drift":   func(e *VerifiedEvent) { e.Provider = "provider_two" },
		"event id drift":   func(e *VerifiedEvent) { e.ProviderEventID = "evt_other" },
		"uppercase digest": func(e *VerifiedEvent) { e.PayloadDigest = strings.ToUpper(e.PayloadDigest) },
		"short digest":     func(e *VerifiedEvent) { e.PayloadDigest = "abcd" },
		"bad event type":   func(e *VerifiedEvent) { e.EventType = "Payment Settled" },
		"empty key id":     func(e *VerifiedEvent) { e.KeyID = "" },
		"zero time":        func(e *VerifiedEvent) { e.OccurredAt = time.Time{} },
		"zero tenant":      func(e *VerifiedEvent) { e.Tenant = "00000000-0000-0000-0000-000000000000" },
		"empty tenant":     func(e *VerifiedEvent) { e.Tenant = "" },
		"malformed tenant": func(e *VerifiedEvent) { e.Tenant = "tenant-one" },
	}
	for name, mutate := range cases {
		event := validEvent()
		mutate(&event)
		if err := validateEvent(validRequest(), event); !errors.Is(err, ErrInvalidCallback) {
			t.Fatalf("%s: error was %v, want ErrInvalidCallback", name, err)
		}
	}
	if err := validateEvent(validRequest(), validEvent()); err != nil {
		t.Fatalf("valid event was rejected: %v", err)
	}
}

func TestAcceptFailsClosedBeforeClaiming(t *testing.T) {
	ctx := context.Background()
	apply := func(context.Context, *sql.Tx, VerifiedEvent) error { return nil }
	request := validRequest()

	inbox, err := New(lazyDB(t), verifierFunc(func(context.Context, VerificationRequest) (VerifiedEvent, error) {
		return validEvent(), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Accept(ctx, request, nil); err == nil {
		t.Fatal("expected an error for a missing applier")
	}
	if _, err := inbox.Accept(nil, request, apply); err == nil {
		t.Fatal("expected an error for a missing context")
	}
	unsigned := request
	unsigned.Signature = nil
	if _, err := inbox.Accept(ctx, unsigned, apply); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("missing signature error was %v, want ErrUnauthenticated", err)
	}

	drifted, err := New(lazyDB(t), verifierFunc(func(context.Context, VerificationRequest) (VerifiedEvent, error) {
		event := validEvent()
		event.ProviderEventID = "evt_other"
		return event, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := drifted.Accept(ctx, request, apply); !errors.Is(err, ErrInvalidCallback) {
		t.Fatalf("identity drift error was %v, want ErrInvalidCallback", err)
	}
}

func TestAcceptMapsVerifierFailuresToStableErrors(t *testing.T) {
	ctx := context.Background()
	apply := func(context.Context, *sql.Tx, VerifiedEvent) error { return nil }

	rejected, err := New(lazyDB(t), verifierFunc(func(context.Context, VerificationRequest) (VerifiedEvent, error) {
		return VerifiedEvent{}, ErrUnauthenticated
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rejected.Accept(ctx, validRequest(), apply); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("rejected error was %v, want ErrUnauthenticated", err)
	}

	broken, err := New(lazyDB(t), verifierFunc(func(context.Context, VerificationRequest) (VerifiedEvent, error) {
		return VerifiedEvent{}, errors.New("key service returned 500")
	}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = broken.Accept(ctx, validRequest(), apply)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unavailable error was %v, want ErrUnavailable", err)
	}
	if strings.Contains(err.Error(), "500") {
		t.Fatal("verifier detail leaked into the caller error")
	}
}
