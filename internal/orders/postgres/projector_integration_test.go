package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/orders"
	"github.com/sanskarpan/keel/internal/orders/outbox"
	"github.com/sanskarpan/keel/internal/orders/projector"
	"github.com/sanskarpan/keel/internal/platform/kafkarelay"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	kafka "github.com/segmentio/kafka-go"
)

func TestPostgreSQLProjectorDefersReplaysAndDeduplicates(t *testing.T) {
	appDB, tenant, appRepo := repositoryTestDB(t)
	projectorDSN := os.Getenv("KEEL_TEST_PROJECTOR_DATABASE_URL")
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if projectorDSN == "" || adminDSN == "" {
		t.Skip("set projector and test-admin database URLs for projection integration coverage")
	}
	projectorDB := integrationDB(t, projectorDSN, 4)
	adminDB := integrationDB(t, adminDSN, 2)
	projectorRepo, err := NewRepository(projectorDB)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	created, err := appRepo.Create(ctx, tenant, testCreate("projector-"+nextUUID()), testMetadata(string(tenant), nextUUID()), "projector-create-"+nextUUID(), "principal:requester-1")
	if err != nil {
		t.Fatal(err)
	}
	metadata := testMetadata(string(tenant), created.Snapshot.OrderID)
	metadata.ActorRef = "principal:requester-1"
	if _, err := appRepo.Submit(ctx, tenant, created.Snapshot.OrderID, 1, testSubmit(), metadata, "projector-submit-"+nextUUID(), "principal:requester-1"); err != nil {
		t.Fatal(err)
	}

	var wireEnvelopes [][]byte
	err = tenancy.WithTenantTx(ctx, appDB, tenant, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT safe_envelope FROM keel_meta.event_outbox WHERE tenant_id=$1 AND aggregate_id=$2 ORDER BY aggregate_version`, string(tenant), created.Snapshot.OrderID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			wireEnvelopes = append(wireEnvelopes, raw)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(wireEnvelopes) != 2 {
		t.Fatalf("canonical envelope count=%d, want two", len(wireEnvelopes))
	}

	processor, err := projector.New(projectorRepo, projector.DefaultConsumerID)
	if err != nil {
		t.Fatal(err)
	}
	baseOffset := time.Now().UnixNano()
	versionTwo := projectionRecord(t, wireEnvelopes[1], baseOffset+1)
	result, err := processor.Process(ctx, string(tenant), versionTwo)
	if err != nil || result.Disposition != projector.Deferred {
		t.Fatalf("version two result=%+v err=%v, want deferred", result, err)
	}
	count, err := processor.ReplayGaps(ctx, string(tenant), 10)
	if err != nil || count != 2 {
		t.Fatalf("replayed count=%d err=%v, want both canonical versions", count, err)
	}
	versionOne := projectionRecord(t, wireEnvelopes[0], baseOffset)
	result, err = processor.Process(ctx, string(tenant), versionOne)
	if err != nil || result.Disposition != projector.Duplicate {
		t.Fatalf("late version-one duplicate result=%+v err=%v", result, err)
	}

	conflictingContent := versionTwo
	var changedEnvelope map[string]any
	if err := json.Unmarshal(conflictingContent.Value, &changedEnvelope); err != nil {
		t.Fatal(err)
	}
	changedEnvelope["event_type"] = string(orders.OrderRejected)
	conflictingContent.Value, err = json.Marshal(changedEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	result, err = processor.Process(ctx, string(tenant), conflictingContent)
	if err != nil || result.Disposition != projector.Quarantined || result.ReasonCode != "source_mismatch" {
		t.Fatalf("same-ID conflicting content result=%+v err=%v", result, err)
	}
	differentID := versionTwo
	differentID.Headers = []projector.Header{
		{Key: "event_id", Value: []byte("cccccccc-cccc-4ccc-8ccc-cccccccccccc")},
		{Key: "schema_version", Value: []byte("1")}, {Key: "aggregate_version", Value: []byte("2")},
	}
	changedEnvelope["event_id"] = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	differentID.Value, err = json.Marshal(changedEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	result, err = processor.Process(ctx, string(tenant), differentID)
	if err != nil || result.Disposition != projector.Quarantined || result.ReasonCode != "source_mismatch" {
		t.Fatalf("same-version different-ID result=%+v err=%v", result, err)
	}
	var tenantClaimRows, transportMismatchRows int
	if err := adminDB.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.event_quarantine WHERE tenant_id=$1 AND event_id=$2`, string(tenant), "cccccccc-cccc-4ccc-8ccc-cccccccccccc").Scan(&tenantClaimRows); err != nil {
		t.Fatal(err)
	}
	if err := adminDB.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.transport_quarantine WHERE source_topic=$1 AND partition_id=$2 AND message_offset=$3 AND reason_code='source_mismatch'`, differentID.Topic, differentID.Partition, differentID.Offset).Scan(&transportMismatchRows); err != nil {
		t.Fatal(err)
	}
	if tenantClaimRows != 0 || transportMismatchRows != 1 {
		t.Fatalf("unmatched tenant claim quarantine rows: tenant=%d transport=%d", tenantClaimRows, transportMismatchRows)
	}

	var appliedVersion int64
	var status sql.NullString
	err = tenancy.WithTenantTx(ctx, projectorDB, tenant, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT applied_version,status FROM keel_meta.order_projections WHERE tenant_id=$1 AND aggregate_id=$2`, string(tenant), created.Snapshot.OrderID).Scan(&appliedVersion, &status)
	})
	if err != nil || appliedVersion != 2 || !status.Valid || status.String != string(orders.Submitted) {
		t.Fatalf("projected state version=%d status=%v err=%v", appliedVersion, status, err)
	}

	otherTenant := mustTenant(t, nextUUID())
	err = tenancy.WithTenantTx(ctx, projectorDB, otherTenant, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		var visible int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.order_projections WHERE tenant_id=$1`, string(tenant)).Scan(&visible); err != nil {
			return err
		}
		if visible != 0 {
			t.Fatalf("cross-tenant projector query exposed %d rows", visible)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := projectorDB.ExecContext(ctx, `UPDATE keel_meta.event_outbox SET safe_envelope=safe_envelope WHERE tenant_id=$1`, string(tenant)); err == nil {
		t.Fatal("projector role unexpectedly mutated canonical outbox history")
	}

	malformed := projector.Record{Topic: "keel.test.orders.v1", Partition: 3, Offset: 81, Value: []byte(`{"tenant_id":"untrusted"}`)}
	result, err = processor.Process(ctx, string(tenant), malformed)
	if err != nil || result.Disposition != projector.Quarantined {
		t.Fatalf("malformed transport result=%+v err=%v", result, err)
	}
	if duplicate, err := processor.Process(ctx, string(tenant), malformed); err != nil || duplicate.Disposition != projector.Quarantined {
		t.Fatalf("malformed redelivery result=%+v err=%v", duplicate, err)
	}
	conflictingOffset := malformed
	conflictingOffset.Value = []byte(`{"tenant_id":"different untrusted value"}`)
	if _, err := processor.Process(ctx, string(tenant), conflictingOffset); err == nil {
		t.Fatal("same Kafka offset with a different payload digest was accepted")
	}
	var storedHash []byte
	if err := adminDB.QueryRowContext(ctx, `SELECT payload_hash FROM keel_meta.transport_quarantine WHERE source_topic=$1 AND partition_id=$2 AND message_offset=$3`, malformed.Topic, malformed.Partition, malformed.Offset).Scan(&storedHash); err != nil {
		t.Fatal(err)
	}
	if len(storedHash) != 32 {
		t.Fatalf("transport quarantine stored digest length=%d, want 32", len(storedHash))
	}
}

func TestPostgreSQLProjectorBlocksCorruptCanonicalSource(t *testing.T) {
	appDB, tenant, appRepo := repositoryTestDB(t)
	projectorDSN := os.Getenv("KEEL_TEST_PROJECTOR_DATABASE_URL")
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if projectorDSN == "" || adminDSN == "" {
		t.Skip("set projector and test-admin database URLs for corrupt-source coverage")
	}
	projectorDB := integrationDB(t, projectorDSN, 2)
	adminDB := integrationDB(t, adminDSN, 2)
	projectorRepo, err := NewRepository(projectorDB)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	created, err := appRepo.Create(ctx, tenant, testCreate("projector-corrupt-"+nextUUID()), testMetadata(string(tenant), nextUUID()), "projector-corrupt-create-"+nextUUID(), "principal:requester-1")
	if err != nil {
		t.Fatal(err)
	}
	events, err := appRepo.Events(ctx, tenant, created.Snapshot.OrderID)
	if err != nil || len(events) != 1 {
		t.Fatalf("order events=%d err=%v", len(events), err)
	}
	var raw []byte
	err = tenancy.WithTenantTx(ctx, appDB, tenant, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT safe_envelope FROM keel_meta.event_outbox WHERE tenant_id=$1 AND event_id=$2`, string(tenant), events[0].Metadata.EventID).Scan(&raw)
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adminDB.ExecContext(ctx, `UPDATE keel_meta.event_outbox SET safe_envelope='{}'::jsonb WHERE tenant_id=$1 AND event_id=$2`, string(tenant), events[0].Metadata.EventID); err != nil {
		t.Fatal(err)
	}
	processor, err := projector.New(projectorRepo, "")
	if err != nil {
		t.Fatal(err)
	}
	record := projectionRecord(t, raw, time.Now().UnixNano())
	result, err := processor.Process(ctx, string(tenant), record)
	if err != nil || result.Disposition != projector.Quarantined || result.ReasonCode != "source_event_invalid" {
		t.Fatalf("corrupt canonical result=%+v err=%v", result, err)
	}
	var blocked, reason string
	var version int64
	err = tenancy.WithTenantTx(ctx, projectorDB, tenant, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT state,last_error_code FROM keel_meta.deferred_events WHERE tenant_id=$1 AND consumer_id=$2 AND aggregate_id=$3 AND aggregate_version=1`, string(tenant), projector.DefaultConsumerID, created.Snapshot.OrderID).Scan(&blocked, &reason); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `SELECT applied_version FROM keel_meta.order_projections WHERE tenant_id=$1 AND aggregate_id=$2`, string(tenant), created.Snapshot.OrderID).Scan(&version)
	})
	if err != nil || blocked != "blocked" || reason != "source_event_invalid" || version != 0 {
		t.Fatalf("corrupt source block=%q reason=%q applied_version=%d err=%v", blocked, reason, version, err)
	}
	var quarantines int
	if err := adminDB.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.event_quarantine WHERE tenant_id=$1 AND event_id=$2 AND reason_code='source_event_invalid'`, string(tenant), events[0].Metadata.EventID).Scan(&quarantines); err != nil {
		t.Fatal(err)
	}
	if quarantines != 1 {
		t.Fatalf("corrupt source quarantine count=%d, want one", quarantines)
	}
}

var (
	errOffsetCommitNotApplied = errors.New("injected Kafka offset commit failure before acceptance")
	errOffsetCommitAckLost    = errors.New("injected lost acknowledgement after Kafka accepted offset commit")
	k17ConsumerTopic          = "keel.k17-consumer.orders.v1"
)

type failTargetCommitReader struct {
	kafkarelay.GroupReader
	eventID string
	failed  bool
}

func (r *failTargetCommitReader) CommitMessages(ctx context.Context, messages ...kafka.Message) error {
	for _, message := range messages {
		for _, header := range message.Headers {
			if header.Key == "event_id" && string(header.Value) == r.eventID && !r.failed {
				r.failed = true
				return errOffsetCommitNotApplied
			}
		}
	}
	return r.GroupReader.CommitMessages(ctx, messages...)
}

type loseTargetCommitAckReader struct {
	kafkarelay.GroupReader
	eventID string
	lost    bool
}

func (r *loseTargetCommitAckReader) CommitMessages(ctx context.Context, messages ...kafka.Message) error {
	for _, message := range messages {
		for _, header := range message.Headers {
			if header.Key == "event_id" && string(header.Value) == r.eventID && !r.lost {
				if err := r.GroupReader.CommitMessages(ctx, messages...); err != nil {
					return err
				}
				r.lost = true
				return errOffsetCommitAckLost
			}
		}
	}
	return r.GroupReader.CommitMessages(ctx, messages...)
}

func TestPostgreSQLKafkaConsumerReplaysUncommittedDBEffectAcrossGroupRebalance(t *testing.T) {
	_, tenant, appRepo := repositoryTestDB(t)
	projectorDSN := os.Getenv("KEEL_TEST_PROJECTOR_DATABASE_URL")
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	workerDSN := os.Getenv("KEEL_TEST_WORKER_DATABASE_URL")
	brokers := strings.Split(os.Getenv("KEEL_TEST_KAFKA_BROKERS"), ",")
	if projectorDSN == "" || adminDSN == "" || workerDSN == "" || strings.TrimSpace(brokers[0]) == "" {
		t.Skip("set projector, worker, test-admin, and Kafka test endpoints for consumer rebalance coverage")
	}
	topic := k17ConsumerTopic
	projectorDB := integrationDB(t, projectorDSN, 3)
	adminDB := integrationDB(t, adminDSN, 3)
	workerDB := integrationDB(t, workerDSN, 3)
	projectorRepo, err := NewRepository(projectorDB)
	if err != nil {
		t.Fatal(err)
	}
	workerRepo, err := NewRepository(workerDB)
	if err != nil {
		t.Fatal(err)
	}
	processor, err := projector.New(projectorRepo, projector.DefaultConsumerID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	created, err := appRepo.Create(ctx, tenant, testCreate("consumer-rebalance-"+nextUUID()), testMetadata(string(tenant), nextUUID()), "consumer-rebalance-create-"+nextUUID(), "principal:requester-1")
	if err != nil {
		t.Fatal(err)
	}
	meta := testMetadata(string(tenant), created.Snapshot.OrderID)
	meta.ActorRef = "principal:requester-1"
	if _, err := appRepo.Submit(ctx, tenant, created.Snapshot.OrderID, 1, testSubmit(), meta, "consumer-rebalance-submit-"+nextUUID(), "principal:requester-1"); err != nil {
		t.Fatal(err)
	}
	events, err := appRepo.Events(ctx, tenant, created.Snapshot.OrderID)
	if err != nil || len(events) != 2 {
		t.Fatalf("source order events=%d err=%v", len(events), err)
	}
	broker, err := kafkarelay.NewLocalSyntheticBroker(brokers, topic)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	publisher, err := outbox.NewPublisher(workerRepo, broker, outbox.Config{LeaseDuration: 5 * time.Second, PublishTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	firstPublish, err := publisher.RunOnce(ctx, string(tenant), "consumer-rebalance-relay")
	if err != nil || !firstPublish.Published || firstPublish.EventID != events[0].Metadata.EventID {
		t.Fatalf("first order event publish=%+v err=%v", firstPublish, err)
	}
	groupID := "keel-k17-consumer-test"
	reader1 := kafka.NewReader(kafka.ReaderConfig{Brokers: brokers, Topic: topic, GroupID: groupID, MinBytes: 1, MaxBytes: 1 << 20, MaxWait: 100 * time.Millisecond, CommitInterval: 0, StartOffset: kafka.FirstOffset})
	consumer1, err := kafkarelay.NewConsumerWithReader(&failTargetCommitReader{GroupReader: reader1, eventID: events[0].Metadata.EventID}, processor)
	if err != nil {
		t.Fatal(err)
	}
	commitNotApplied := false
	for attempts := 0; attempts < 100; attempts++ {
		if _, err := consumer1.RunOnce(ctx); errors.Is(err, errOffsetCommitNotApplied) {
			commitNotApplied = true
			break
		} else if err != nil {
			t.Fatalf("consume before unaccepted commit boundary: %v", err)
		}
	}
	if !commitNotApplied {
		t.Fatal("consumer did not reach the target event before its rejected offset commit")
	}
	if err := consumer1.Close(); err != nil {
		t.Fatal(err)
	}
	assertProjectionVersion(t, adminDB, string(tenant), created.Snapshot.OrderID, 1, string(orders.Draft))

	// Closing the first group member simulates process loss/rebalance. Since its DB effect
	// committed but the Kafka offset did not, the new member must receive and deduplicate v1.
	reader2 := kafka.NewReader(kafka.ReaderConfig{Brokers: brokers, Topic: topic, GroupID: groupID, MinBytes: 1, MaxBytes: 1 << 20, MaxWait: 100 * time.Millisecond, CommitInterval: 0, StartOffset: kafka.FirstOffset})
	consumer2, err := kafkarelay.NewConsumerWithReader(&loseTargetCommitAckReader{GroupReader: reader2, eventID: events[1].Metadata.EventID}, processor)
	if err != nil {
		t.Fatal(err)
	}
	result, err := consumer2.RunOnce(ctx)
	if err != nil || result.Disposition != projector.Duplicate {
		_ = consumer2.Close()
		t.Fatalf("redelivery after group rebalance result=%+v err=%v", result, err)
	}
	secondPublish, err := publisher.RunOnce(ctx, string(tenant), "consumer-rebalance-relay")
	if err != nil || !secondPublish.Published || secondPublish.EventID != events[1].Metadata.EventID {
		_ = consumer2.Close()
		t.Fatalf("second order event publish=%+v err=%v", secondPublish, err)
	}
	commitAcceptedAckLost := false
	for attempts := 0; attempts < 100; attempts++ {
		if _, err := consumer2.RunOnce(ctx); errors.Is(err, errOffsetCommitAckLost) {
			commitAcceptedAckLost = true
			break
		} else if err != nil {
			_ = consumer2.Close()
			t.Fatalf("consume before accepted offset commit acknowledgement loss: %v", err)
		}
	}
	if !commitAcceptedAckLost {
		_ = consumer2.Close()
		t.Fatal("consumer did not reach version two before its accepted offset commit acknowledgement was lost")
	}
	if err := consumer2.Close(); err != nil {
		t.Fatal(err)
	}
	assertProjectionVersion(t, adminDB, string(tenant), created.Snapshot.OrderID, 2, string(orders.Submitted))
	// This time Kafka did commit the offset; only the response was lost. Restart must continue
	// after v2 without reapplying it, which is the other valid outcome of an ambiguous commit.
	consumer3, err := kafkarelay.NewLocalSyntheticConsumer(brokers, topic, groupID, processor)
	if err != nil {
		t.Fatal(err)
	}
	noRedeliveryCtx, stopWaiting := context.WithTimeout(ctx, 500*time.Millisecond)
	defer stopWaiting()
	if _, err := consumer3.RunOnce(noRedeliveryCtx); !errors.Is(err, context.DeadlineExceeded) {
		_ = consumer3.Close()
		t.Fatalf("accepted offset was redelivered after acknowledgement loss: %v", err)
	}
	if err := consumer3.Close(); err != nil {
		t.Fatal(err)
	}
	var inboxCount int
	if err := adminDB.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.event_inbox WHERE tenant_id=$1 AND consumer_id=$2 AND aggregate_id=$3 AND apply_state='applied'`, string(tenant), projector.DefaultConsumerID, created.Snapshot.OrderID).Scan(&inboxCount); err != nil {
		t.Fatal(err)
	}
	if inboxCount != 2 {
		t.Fatalf("applied inbox rows=%d after duplicate replay, want exactly two logical effects", inboxCount)
	}
}

func assertProjectionVersion(t *testing.T, db *sql.DB, tenant, orderID string, wantVersion int, wantStatus string) {
	t.Helper()
	version, status := readProjectionVersion(t, db, tenant, orderID)
	if version != wantVersion || status != wantStatus {
		t.Fatalf("projection version/status=%d/%q, want %d/%q", version, status, wantVersion, wantStatus)
	}
}

func readProjectionVersion(t *testing.T, db *sql.DB, tenant, orderID string) (int, string) {
	t.Helper()
	var version int
	var status sql.NullString
	if err := db.QueryRowContext(context.Background(), `SELECT applied_version,status FROM keel_meta.order_projections WHERE tenant_id=$1 AND aggregate_id=$2`, tenant, orderID).Scan(&version, &status); err != nil {
		t.Fatal(err)
	}
	if !status.Valid {
		return version, ""
	}
	return version, status.String
}

func projectionRecord(t *testing.T, raw []byte, offset int64) projector.Record {
	t.Helper()
	var envelope projector.Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	return projector.Record{
		Topic: "keel.test.orders.v1", Partition: 0, Offset: offset,
		Key: []byte(envelope.TenantID + "/" + envelope.AggregateID), Value: raw,
		Headers: []projector.Header{
			{Key: "event_id", Value: []byte(envelope.EventID)},
			{Key: "schema_version", Value: []byte("1")},
			{Key: "aggregate_version", Value: []byte(strconv.FormatInt(envelope.AggregateVersion, 10))},
		},
	}
}
