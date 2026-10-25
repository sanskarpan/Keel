package worker

import (
	"context"
	"database/sql"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/delivery/webhook/postgres"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

type staticResolver struct {
	addrs []net.IPAddr
}

func (r staticResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return r.addrs, nil
}

func replayExecutionDatabases(t *testing.T) (*sql.DB, *sql.DB, *sql.DB, *sql.DB) {
	t.Helper()
	appDSN := os.Getenv("KEEL_TEST_DATABASE_URL")
	webhookDSN := os.Getenv("KEEL_TEST_WEBHOOK_DATABASE_URL")
	operatorDSN := os.Getenv("KEEL_TEST_OPERATOR_DATABASE_URL")
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if appDSN == "" || webhookDSN == "" || operatorDSN == "" || adminDSN == "" {
		t.Skip("set app, webhook, operator and admin DSNs for replay execution coverage")
	}
	open := func(dsn string) *sql.DB {
		db, err := sql.Open("pgx", dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	return open(appDSN), open(webhookDSN), open(operatorDSN), open(adminDSN)
}

func insertReplayOutbox(t *testing.T, adminDB *sql.DB, tenant tenancy.TenantID, eventID string) {
	t.Helper()
	ctx := context.Background()
	orderID := uuid.NewString()
	hash := make([]byte, 32)
	if _, err := adminDB.ExecContext(ctx,
		`INSERT INTO keel_meta.order_heads
		 (tenant_id,order_id,external_reference,supplier_id,status,version,command_snapshot,snapshot_hash)
		 VALUES ($1,$2,$3,$4,'draft',1,'{}'::jsonb,$5)`,
		string(tenant), orderID, "ref-"+uuid.NewString(), uuid.NewString(), hash); err != nil {
		t.Fatalf("insert order head: %v", err)
	}
	if _, err := adminDB.ExecContext(ctx,
		`INSERT INTO keel_meta.order_events
		 (tenant_id,order_id,aggregate_version,event_id,event_type,event_data,event_hash,occurred_at)
		 VALUES ($1,$2,1,$3,'order.created','{}'::jsonb,$4,clock_timestamp())`,
		string(tenant), orderID, eventID, hash); err != nil {
		t.Fatalf("insert order event: %v", err)
	}
	if _, err := adminDB.ExecContext(ctx,
		`INSERT INTO keel_meta.event_outbox
		 (tenant_id,event_id,aggregate_id,aggregate_version,event_type,schema_version,safe_envelope)
		 VALUES ($1,$2,$3,1,'order.created',1,$4::jsonb)`,
		string(tenant), eventID, orderID, `{"event_id":"`+eventID+`"}`); err != nil {
		t.Fatalf("insert outbox event: %v", err)
	}
}

func insertReplayDelivery(t *testing.T, adminDB *sql.DB, tenant tenancy.TenantID, eventID, endpointID string) string {
	t.Helper()
	ctx := context.Background()
	deliveryID := "whd_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := adminDB.ExecContext(ctx,
		`INSERT INTO keel_meta.webhook_deliveries
		 (tenant_id,event_id,endpoint_id,subscription_version,delivery_id)
		 VALUES ($1,$2,$3,1,$4)`,
		string(tenant), eventID, endpointID, deliveryID); err != nil {
		t.Fatalf("insert replay delivery: %v", err)
	}
	if _, err := adminDB.ExecContext(ctx,
		`UPDATE keel_meta.webhook_delivery_state SET next_attempt_at=$3
		  WHERE tenant_id=$1 AND delivery_id=$2`,
		string(tenant), deliveryID, time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatalf("schedule replay delivery: %v", err)
	}
	return deliveryID
}

func replayDeliveryState(t *testing.T, adminDB *sql.DB, tenant tenancy.TenantID, deliveryID string) (string, int, time.Time) {
	t.Helper()
	var state string
	var attempts int
	var firstAttempt time.Time
	if err := adminDB.QueryRowContext(context.Background(),
		`SELECT state,attempts,first_attempt_at FROM keel_meta.webhook_delivery_state
		  WHERE tenant_id=$1 AND delivery_id=$2`,
		string(tenant), deliveryID).Scan(&state, &attempts, &firstAttempt); err != nil {
		t.Fatal(err)
	}
	return state, attempts, firstAttempt.UTC()
}

type receivedAttempt struct {
	deliveryID string
	attemptID  string
	signature  string
}

func TestReplayExecutionRedeliversThroughWorkerLoop(t *testing.T) {
	appDB, webhookDB, operatorDB, adminDB := replayExecutionDatabases(t)
	ctx := context.Background()
	tenant, err := tenancy.ParseTenantID(uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}

	var failing atomic.Bool
	failing.Store(true)
	var mu sync.Mutex
	var received []receivedAttempt
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/orders" {
			t.Errorf("request = %s %s, want POST /orders", request.Method, request.URL.Path)
		}
		mu.Lock()
		received = append(received, receivedAttempt{
			deliveryID: request.Header.Get(webhook.HeaderDeliveryID),
			attemptID:  request.Header.Get(webhook.HeaderAttemptID),
			signature:  request.Header.Get(webhook.HeaderSignature),
		})
		mu.Unlock()
		if failing.Load() {
			http.Error(response, "receiver is down", http.StatusBadRequest)
			return
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	egress, err := webhook.NewEgress(webhook.EgressPolicy{Timeout: 5 * time.Second}, staticResolver{
		addrs: []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := egress.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("egress transport has an unexpected type")
	}
	transport.TLSClientConfig.InsecureSkipVerify = true
	address := server.Listener.Addr().String()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport.DialContext = func(dialCtx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(dialCtx, network, address)
	}
	keyring, err := webhook.NewKeyring(webhook.Key{
		ID:     "replay_key_2026",
		Secret: []byte("0123456789abcdef0123456789abcdef"),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := webhook.NewExecutor(egress, keyring)
	if err != nil {
		t.Fatal(err)
	}

	registry, err := postgres.NewRegistry(appDB)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := registry.Register(ctx, tenant, webhook.EndpointRegistration{
		ID:                  "ep_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		URL:                 "https://hooks.example.com/orders",
		KeyID:               "replay_key_2026",
		SubscriptionVersion: 1,
	}, 0)
	if err != nil {
		t.Fatalf("register endpoint: %v", err)
	}

	eventID := uuid.NewString()
	insertReplayOutbox(t, adminDB, tenant, eventID)
	deliveryID := insertReplayDelivery(t, adminDB, tenant, eventID, endpoint.ID)

	store, err := postgres.New(webhookDB)
	if err != nil {
		t.Fatal(err)
	}
	schedule, err := webhook.NewScheduler(webhook.DefaultRetryPolicy())
	if err != nil {
		t.Fatal(err)
	}
	runner, err := New(store, store, executor, schedule, webhook.DefaultBreakerPolicy())
	if err != nil {
		t.Fatal(err)
	}

	first, err := runner.Run(ctx, tenant, 5)
	if err != nil {
		t.Fatalf("first worker run: %v", err)
	}
	if first.Leased != 1 || first.Failed != 1 || first.Delivered != 0 {
		t.Fatalf("first report = %+v, want one leased permanent failure", first)
	}
	state, attempts, firstAttempt := replayDeliveryState(t, adminDB, tenant, deliveryID)
	if state != "failed" || attempts != 1 || firstAttempt.IsZero() {
		t.Fatalf("after failure state=%q attempts=%d first=%v", state, attempts, firstAttempt)
	}

	operatorStore, err := postgres.New(operatorDB)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := operatorStore.AuthorizeReplay(ctx, webhook.ReplayRequest{
		Tenant:      tenant,
		ReplayID:    "rep_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		DeliveryID:  deliveryID,
		RequestedBy: "operator@example.com",
		Reason:      "receiver recovered, redeliver the failed attempt",
	})
	if err != nil {
		t.Fatalf("authorize replay: %v", err)
	}
	if !authorization.Created || authorization.PriorState != webhook.StateFailed || authorization.PriorAttempts != 1 {
		t.Fatalf("replay authorization = %+v", authorization)
	}

	failing.Store(false)
	second, err := runner.Run(ctx, tenant, 5)
	if err != nil {
		t.Fatalf("second worker run: %v", err)
	}
	if second.Leased != 1 || second.Delivered != 1 {
		t.Fatalf("second report = %+v, want one leased redelivery", second)
	}
	state, attempts, replayedFirst := replayDeliveryState(t, adminDB, tenant, deliveryID)
	if state != "delivered" || attempts != 2 {
		t.Fatalf("after replay state=%q attempts=%d, want delivered/2", state, attempts)
	}
	if !replayedFirst.Equal(firstAttempt) {
		t.Fatalf("replay changed first_attempt_at from %v to %v", firstAttempt, replayedFirst)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 2 {
		t.Fatalf("receiver requests = %d, want 2", len(received))
	}
	for _, attempt := range received {
		if attempt.deliveryID != deliveryID {
			t.Fatalf("delivery header = %q, want %q", attempt.deliveryID, deliveryID)
		}
		if !strings.Contains(attempt.signature, "kid=replay_key_2026") {
			t.Fatalf("signature header = %q, want test key", attempt.signature)
		}
	}
	if received[0].attemptID == "" || received[1].attemptID == "" || received[0].attemptID == received[1].attemptID {
		t.Fatalf("attempt headers = %+v, want two fresh identities", received)
	}

	var attemptRows int
	if err := adminDB.QueryRowContext(ctx,
		`SELECT count(*) FROM keel_meta.webhook_delivery_attempts WHERE tenant_id=$1 AND delivery_id=$2`,
		string(tenant), deliveryID).Scan(&attemptRows); err != nil {
		t.Fatal(err)
	}
	if attemptRows != 2 {
		t.Fatalf("attempt rows = %d, want 2", attemptRows)
	}
}
