package projector

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/orders"
)

const (
	testTenant = "11111111-1111-4111-8111-111111111111"
	testOrder  = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	testEvent  = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
)

type fakeStore struct {
	consumer            string
	tenant              string
	envelope            Envelope
	digest              [32]byte
	result              Result
	err                 error
	limit               int
	quarantineSource    string
	quarantinePartition int
	quarantineOffset    int64
	quarantineHash      [32]byte
	quarantineReason    string
}

func (s *fakeStore) Apply(_ context.Context, consumer string, envelope Envelope, digest [32]byte) (Result, error) {
	s.consumer, s.tenant, s.envelope, s.digest = consumer, envelope.TenantID, envelope, digest
	return s.result, s.err
}
func (s *fakeStore) ReplayGaps(_ context.Context, tenant, consumer string, limit int) (int, error) {
	s.tenant, s.consumer, s.limit = tenant, consumer, limit
	return 2, s.err
}
func (s *fakeStore) QuarantineTransport(_ context.Context, topic string, partition int, offset int64, hash [32]byte, reason string) error {
	s.quarantineSource, s.quarantinePartition, s.quarantineOffset, s.quarantineHash, s.quarantineReason = topic, partition, offset, hash, reason
	return s.err
}

func TestDecodeValidatesEnvelopeHeadersAndTenant(t *testing.T) {
	raw := []byte(`{"schema_version":1,"event_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","tenant_id":"11111111-1111-4111-8111-111111111111","aggregate_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","aggregate_version":1,"event_type":"order.created","occurred_at":"2026-01-02T03:04:05Z"}`)
	record := testRecord(raw, "1")
	envelope, digest, err := Decode(testTenant, record)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.EventID != testEvent || envelope.AggregateVersion != 1 || digest == ([32]byte{}) {
		t.Fatalf("decoded envelope=%+v digest=%x", envelope, digest)
	}
	if got := sha256.Sum256(mustCanonicalJSON(t, envelope)); got != digest {
		t.Fatal("digest is not over normalized canonical envelope")
	}
	if _, _, err := Decode("22222222-2222-4222-8222-222222222222", record); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("cross-tenant envelope error=%v", err)
	}
}

func TestDecodeRejectsInvalidAndConflictingTransportMetadata(t *testing.T) {
	valid := testRecord(validEnvelope(t, 2, orders.OrderSubmitted), "2")
	cases := map[string]Record{
		"wrong key":          func() Record { r := valid; r.Key = []byte(testTenant + "/" + testEvent); return r }(),
		"wrong event header": func() Record { r := valid; r.Headers[0].Value = []byte(testOrder); return r }(),
		"duplicate event header": func() Record {
			r := valid
			r.Headers = append(append([]Header(nil), r.Headers...), Header{Key: "event_id", Value: []byte(testEvent)})
			return r
		}(),
		"duplicate JSON key": func() Record {
			r := valid
			r.Value = []byte(`{"schema_version":1,"event_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","tenant_id":"11111111-1111-4111-8111-111111111111","aggregate_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","aggregate_version":2,"aggregate_version":2,"event_type":"order.submitted","occurred_at":"2026-01-02T03:04:05Z"}`)
			return r
		}(),
		"unknown field": func() Record {
			r := valid
			r.Value = append(append([]byte(nil), r.Value[:len(r.Value)-1]...), []byte(`,"private":"do-not-accept"}`)...)
			return r
		}(),
		"trailing json": func() Record { r := valid; r.Value = append(r.Value, []byte(` {}`)...); return r }(),
		"oversized":     func() Record { r := valid; r.Value = make([]byte, MaxEnvelopeBytes+1); return r }(),
	}
	for name, record := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Decode(testTenant, record); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("Decode error=%v, want ErrInvalidRecord", err)
			}
		})
	}
}

func TestNextStatusEnforcesAggregateTransitionRules(t *testing.T) {
	var status *orders.Status
	for _, event := range []struct {
		typeOf orders.EventType
		want   orders.Status
	}{
		{orders.OrderCreated, orders.Draft},
		{orders.OrderSubmitted, orders.Submitted},
		{orders.OrderVerificationStarted, orders.Verifying},
		{orders.OrderApproved, orders.Approved},
	} {
		got, err := NextStatus(status, event.typeOf)
		if err != nil || got != event.want {
			t.Fatalf("NextStatus(%v,%s) = %s, %v; want %s", status, event.typeOf, got, err, event.want)
		}
		status = &got
	}
	if _, err := NextStatus(status, orders.OrderCanceled); err == nil {
		t.Fatal("terminal order accepted a cancellation transition")
	}
	if _, err := NextStatus(nil, orders.OrderSubmitted); err == nil {
		t.Fatal("stream without order.created was accepted")
	}
}

func TestProcessorUsesConfiguredConsumerAndDelegatesGapReplay(t *testing.T) {
	store := &fakeStore{result: Result{Disposition: Deferred}}
	processor, err := New(store, DefaultConsumerID)
	if err != nil {
		t.Fatal(err)
	}
	record := testRecord(validEnvelope(t, 2, orders.OrderSubmitted), "2")
	result, err := processor.Process(context.Background(), testTenant, record)
	if err != nil || result.Disposition != Deferred || store.consumer != DefaultConsumerID || store.tenant != testTenant {
		t.Fatalf("process result=%+v err=%v store=%+v", result, err, store)
	}
	replayed, err := processor.ReplayGaps(context.Background(), testTenant, 25)
	if err != nil || replayed != 2 || store.limit != 25 {
		t.Fatalf("replay count=%d err=%v limit=%d", replayed, err, store.limit)
	}
	if _, err := processor.ReplayGaps(context.Background(), testTenant, 501); err == nil {
		t.Fatal("unbounded replay batch was accepted")
	}
}

func TestNewRejectsConsumerIDsWithoutProjectionGenerationIsolation(t *testing.T) {
	if _, err := New(&fakeStore{}, "shadow-orders-v2"); err == nil {
		t.Fatal("second consumer ID accepted without generation-scoped projection storage")
	}
}

func TestProcessorPersistsOnlyMetadataAndDigestForMalformedRecord(t *testing.T) {
	store := &fakeStore{}
	processor, err := New(store, "")
	if err != nil {
		t.Fatal(err)
	}
	record := Record{Topic: "keel.test.orders.v1", Partition: 4, Offset: 91, Value: []byte(`{"tenant_id":"not-trusted"}`)}
	result, err := processor.Process(context.Background(), testTenant, record)
	if err != nil || result.Disposition != Quarantined || result.ReasonCode != "invalid_record" {
		t.Fatalf("malformed record result=%+v err=%v", result, err)
	}
	if store.quarantineSource != record.Topic || store.quarantinePartition != record.Partition || store.quarantineOffset != record.Offset ||
		store.quarantineHash != sha256.Sum256(record.Value) || store.quarantineReason != "invalid_record" {
		t.Fatalf("transport quarantine metadata mismatch: %+v", store)
	}
}

func TestProcessRecordQuarantinesMalformedEnvelopeWithoutTenantClaim(t *testing.T) {
	store := &fakeStore{}
	processor, err := New(store, "")
	if err != nil {
		t.Fatal(err)
	}
	record := Record{Topic: "keel.test.orders.v1", Partition: 2, Offset: 99, Value: []byte(`{"not_json":`)}
	result, err := processor.ProcessRecord(context.Background(), record)
	if err != nil || result.Disposition != Quarantined || result.ReasonCode != "invalid_record" {
		t.Fatalf("malformed no-tenant record result=%+v err=%v", result, err)
	}
	if store.quarantineSource != record.Topic || store.quarantinePartition != record.Partition || store.quarantineOffset != record.Offset || store.quarantineHash != sha256.Sum256(record.Value) || store.quarantineReason != "invalid_record" {
		t.Fatalf("invalid record was not durably routed using transport coordinates: %+v", store)
	}
}

func TestProcessorQuarantinesUnmatchedTenantClaimWithoutTenantScopedWrite(t *testing.T) {
	store := &fakeStore{result: Result{Disposition: Quarantined, ReasonCode: "source_not_found"}}
	processor, err := New(store, "")
	if err != nil {
		t.Fatal(err)
	}
	record := testRecord(validEnvelope(t, 1, orders.OrderCreated), "1")
	result, err := processor.Process(context.Background(), testTenant, record)
	if err != nil || result.Disposition != Quarantined || result.ReasonCode != "source_mismatch" {
		t.Fatalf("unmatched source result=%+v err=%v", result, err)
	}
	if store.quarantineSource != record.Topic || store.quarantineHash != sha256.Sum256(record.Value) || store.quarantineReason != "source_mismatch" {
		t.Fatalf("unmatched claim was not stored using trusted transport coordinates: %+v", store)
	}
}

func testRecord(raw []byte, version string) Record {
	return Record{
		Topic: "keel.test.orders.v1", Partition: 0, Offset: 1, Key: []byte(testTenant + "/" + testOrder), Value: raw,
		Headers: []Header{
			{Key: "event_id", Value: []byte(testEvent)},
			{Key: "schema_version", Value: []byte("1")},
			{Key: "aggregate_version", Value: []byte(version)},
		},
	}
}

func validEnvelope(t *testing.T, version int, eventType orders.EventType) []byte {
	t.Helper()
	raw, err := json.Marshal(Envelope{
		SchemaVersion: 1, EventID: testEvent, TenantID: testTenant, AggregateID: testOrder,
		AggregateVersion: int64(version), EventType: eventType, OccurredAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustCanonicalJSON(t *testing.T, envelope Envelope) []byte {
	t.Helper()
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
