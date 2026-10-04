package kafkarelay

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/sanskarpan/keel/internal/orders/projector"
	kafka "github.com/segmentio/kafka-go"
)

type fakeGroupReader struct {
	message   kafka.Message
	commitErr error
	commits   int
	trace     *[]string
}

func (r *fakeGroupReader) FetchMessage(context.Context) (kafka.Message, error) { return r.message, nil }
func (r *fakeGroupReader) CommitMessages(_ context.Context, messages ...kafka.Message) error {
	r.commits++
	if r.trace != nil {
		*r.trace = append(*r.trace, "commit")
	}
	if len(messages) != 1 || messages[0].Offset != r.message.Offset {
		return errors.New("unexpected committed message")
	}
	err := r.commitErr
	r.commitErr = nil
	return err
}
func (*fakeGroupReader) Close() error { return nil }

type fakeRecordProcessor struct {
	results []projector.Result
	err     error
	calls   int
	trace   *[]string
	got     projector.Record
}

func (p *fakeRecordProcessor) ProcessRecord(_ context.Context, record projector.Record) (projector.Result, error) {
	p.calls++
	p.got = record
	if p.trace != nil {
		*p.trace = append(*p.trace, "process")
	}
	if p.err != nil {
		return projector.Result{}, p.err
	}
	result := p.results[0]
	if len(p.results) > 1 {
		p.results = p.results[1:]
	}
	return result, nil
}

func TestConsumerDurableProcessBeforeCommitAndReplaysLostOffsetCommit(t *testing.T) {
	trace := []string{}
	message := kafka.Message{Topic: "keel.test.orders.v1", Partition: 2, Offset: 41, Key: []byte("key"), Value: []byte(`{"tenant_id":"claim"}`), Headers: []kafka.Header{{Key: "event_id", Value: []byte("first")}, {Key: "event_id", Value: []byte("duplicate")}}}
	reader := &fakeGroupReader{message: message, commitErr: errors.New("commit acknowledgement lost"), trace: &trace}
	processor := &fakeRecordProcessor{results: []projector.Result{{Disposition: projector.Applied}, {Disposition: projector.Duplicate}}, trace: &trace}
	consumer, err := NewConsumerWithReader(reader, processor)
	if err != nil {
		t.Fatal(err)
	}
	result, err := consumer.RunOnce(context.Background())
	if err == nil || result.Disposition != "" || processor.calls != 1 || reader.commits != 1 {
		t.Fatalf("first process/commit boundary result=%+v err=%v process_calls=%d commits=%d", result, err, processor.calls, reader.commits)
	}
	result, err = consumer.RunOnce(context.Background())
	if err != nil || result.Disposition != projector.Duplicate || processor.calls != 2 || reader.commits != 2 {
		t.Fatalf("redelivery after lost commit result=%+v err=%v process_calls=%d commits=%d", result, err, processor.calls, reader.commits)
	}
	if !reflect.DeepEqual(trace, []string{"process", "commit", "process", "commit"}) {
		t.Fatalf("process/commit order=%v", trace)
	}
	if processor.got.Topic != message.Topic || processor.got.Partition != message.Partition || processor.got.Offset != message.Offset || len(processor.got.Headers) != 2 || string(processor.got.Headers[1].Value) != "duplicate" {
		t.Fatalf("adapter did not preserve Kafka coordinates/header occurrences: %+v", processor.got)
	}
}

func TestConsumerNeverCommitsWhenDurableProcessingFailsOrIsAmbiguous(t *testing.T) {
	for name, processor := range map[string]*fakeRecordProcessor{
		"database failure":   {err: errors.New("database transaction failed")},
		"non durable result": {results: []projector.Result{{Disposition: "unknown"}}},
	} {
		t.Run(name, func(t *testing.T) {
			reader := &fakeGroupReader{message: kafka.Message{Offset: 1}}
			consumer, err := NewConsumerWithReader(reader, processor)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := consumer.RunOnce(context.Background()); err == nil || reader.commits != 0 {
				t.Fatalf("process failure err=%v commits=%d", err, reader.commits)
			}
		})
	}
}

func TestNewConsumerRequiresCanonicalOrderTopic(t *testing.T) {
	if _, err := NewConsumer([]string{"localhost:9092"}, "keel.test.jobs.v1", "order-projector", &fakeRecordProcessor{}); err == nil {
		t.Fatal("consumer accepted a non-order topic")
	}
	if _, err := New([]string{"localhost:9092"}, "keel.test.jobs.v1"); err == nil {
		t.Fatal("producer accepted a non-order topic")
	}
	if _, err := New([]string{"localhost:9092"}, "keel."+strings.Repeat("a", 245)+".orders.v1"); err == nil {
		t.Fatal("producer accepted an overlong Kafka topic")
	}
	if _, err := NewConsumer([]string{"localhost:9092"}, "keel.test.orders.v1", "bad group id", &fakeRecordProcessor{}); err == nil {
		t.Fatal("consumer accepted an invalid group ID")
	}
}
