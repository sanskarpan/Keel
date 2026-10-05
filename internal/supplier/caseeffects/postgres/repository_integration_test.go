package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/supplier/cases"
	casepg "github.com/sanskarpan/keel/internal/supplier/cases/postgres"
)

func effectRoleDB(t *testing.T, dsn, role, password string) *sql.DB {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(role, password)
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(4)
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestPostgreSQLReminderEffectsAreScheduledFencedAndTerminalAware(t *testing.T) {
	appDSN, workerDSN, adminDSN := os.Getenv("KEEL_TEST_DATABASE_URL"), os.Getenv("KEEL_TEST_WORKER_DATABASE_URL"), os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if appDSN == "" || workerDSN == "" || adminDSN == "" {
		t.Skip("set app, worker and admin PostgreSQL URLs to run reminder effect integration tests")
	}
	appDB := effectRoleDB(t, appDSN, "keel_local_app", "keel-app-local-only")
	workerDB := effectRoleDB(t, workerDSN, "keel_local_worker", "keel-worker-local-only")
	adminDB := effectRoleDB(t, adminDSN, "postgres", "keel-local-only")
	casesRepo, err := casepg.New(appDB)
	if err != nil {
		t.Fatal(err)
	}
	effects, err := New(workerDB)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tenant, _ := tenancy.ParseTenantID(effectUUID(t))
	create := func() (cases.Case, string) {
		policyID, supplierID, key := effectUUID(t), effectUUID(t), effectUUID(t)
		policy := cases.Policy{TenantID: string(tenant), PolicyID: policyID, Version: 1, Name: "Reminder effect", Deadline: 4 * time.Hour, Steps: []cases.ReviewStep{{Key: "review", Role: "risk:reviewer"}}}
		if _, err := casesRepo.PublishPolicy(ctx, tenant, policy, "principal:policy-admin"); err != nil {
			t.Fatal(err)
		}
		if _, err := adminDB.ExecContext(ctx, `INSERT INTO keel_meta.supplier_case_reviewer_grants(tenant_id,principal_ref,role_key) VALUES ($1,'principal:effect-reviewer','risk:reviewer') ON CONFLICT (tenant_id,principal_ref,role_key) DO UPDATE SET granted_at=clock_timestamp(),revoked_at=NULL`, string(tenant)); err != nil {
			t.Fatal(err)
		}
		created, err := casesRepo.Create(ctx, tenant, key, supplierID, policyID, 1, "principal:requester")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := casesRepo.Submit(ctx, tenant, created.CaseID, "principal:requester"); err != nil {
			t.Fatal(err)
		}
		return created, policyID
	}
	first, _ := create()
	assertScheduledEffects(t,ctx,adminDB,tenant,first.CaseID)
	forceDueReminder(t,ctx,adminDB,tenant,first.CaseID)
	if _, err := appDB.QueryContext(ctx, `SELECT effect_id FROM keel_meta.supplier_case_activity_effects WHERE tenant_id=$1`, string(tenant)); err == nil {
		t.Fatal("case application role read the worker-only activity ledger")
	}
	var effectID string
	if err := adminDB.QueryRowContext(ctx, `SELECT effect_id FROM keel_meta.supplier_case_activity_effects WHERE tenant_id=$1 AND case_id=$2 AND effect_type='case_reminder' AND occurrence='midpoint' ORDER BY created_at DESC LIMIT 1`, string(tenant), first.CaseID).Scan(&effectID); err != nil {
		t.Fatal(err)
	}
	if _, err := adminDB.ExecContext(ctx, `UPDATE keel_meta.supplier_case_activity_effects SET payload_digest=decode(repeat('0',64),'hex') WHERE tenant_id=$1 AND effect_id=$2`, string(tenant), effectID); err == nil {
		t.Fatal("effect payload digest was mutable")
	}
	ownerA, ownerB := effectUUID(t), effectUUID(t)
	leaseA, found, err := effects.Claim(ctx, tenant, ownerA, 10*time.Second)
	if err != nil || !found {
		t.Fatalf("initial claim failed: found=%v err=%v", found, err)
	}
	reminder, active, err := effects.LoadContext(ctx, leaseA)
	if err != nil || !active || reminder.CaseState != "submitted" || !containsRecipient(reminder.Recipients, "principal:effect-reviewer") || containsRecipient(reminder.Recipients, "principal:requester") {
		t.Fatalf("reminder context leaked/omitted current recipients: %+v active=%v err=%v", reminder, active, err)
	}
	if _, err := adminDB.ExecContext(ctx, `UPDATE keel_meta.supplier_case_activity_effects SET lease_expires_at=clock_timestamp()-interval '1 second',lease_epoch=lease_epoch+1 WHERE tenant_id=$1 AND effect_id=$2`, string(tenant), leaseA.EffectID); err != nil {
		t.Fatal(err)
	}
	leaseB, found, err := effects.Claim(ctx, tenant, ownerB, time.Minute)
	if err != nil || !found || leaseB.Epoch <= leaseA.Epoch {
		t.Fatalf("expired effect not fenced on reclaim: A=%+v B=%+v found=%v err=%v", leaseA, leaseB, found, err)
	}
	if err := effects.Complete(ctx, leaseA); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("stale effect owner completed reclaimed work: %v", err)
	}
	if err := effects.Complete(ctx, leaseB); err != nil {
		t.Fatal(err)
	}
	otherTenant, _ := tenancy.ParseTenantID(effectUUID(t))
	if _, found, err := effects.Claim(ctx, otherTenant, effectUUID(t), time.Minute); err != nil || found {
		t.Fatalf("cross-tenant worker observed an effect: found=%v err=%v", found, err)
	}

	second, _ := create()
	forceDueReminder(t,ctx,adminDB,tenant,second.CaseID)
	lease, found, err := effects.Claim(ctx, tenant, effectUUID(t), time.Minute)
	if err != nil || !found {
		t.Fatalf("second reminder claim failed: %v %v", found, err)
	}
	canceled, err := casesRepo.Cancel(ctx, tenant, second.CaseID, effectUUID(t), "supplier withdrew", "principal:requester")
	if err != nil {
		t.Fatal(err)
	}
	if canceled.Status != cases.Canceled || lease.CaseID != second.CaseID {
		t.Fatalf("cancellation/lease targeted wrong lifecycle: case=%s status=%s lease=%s", second.CaseID, canceled.Status, lease.CaseID)
	}
	if _, active, err := effects.LoadContext(ctx, lease); err != nil || active {
		t.Fatalf("terminal case retained reminder context: active=%v err=%v", active, err)
	}
	if err := effects.CompleteNoop(ctx, lease); err != nil {
		t.Fatalf("terminal effect could not be acknowledged as a no-op: %v", err)
	}

	third, _ := create()
	forceDueReminder(t, ctx, adminDB, tenant, third.CaseID)
	retryLease, found, err := effects.Claim(ctx, tenant, effectUUID(t), time.Minute)
	if err != nil || !found || retryLease.CaseID != third.CaseID {
		t.Fatalf("retry test claim failed: lease=%+v found=%v err=%v", retryLease, found, err)
	}
	if err := effects.Fail(ctx, retryLease, 5*time.Second, "sink_timeout"); err != nil {
		t.Fatal(err)
	}
	var state, errorCode string
	var attempts int
	var available time.Time
	if err := adminDB.QueryRowContext(ctx, `SELECT effect_state,attempt_count,last_error_code,available_at FROM keel_meta.supplier_case_activity_effects WHERE tenant_id=$1 AND effect_id=$2`, string(tenant), retryLease.EffectID).Scan(&state, &attempts, &errorCode, &available); err != nil {
		t.Fatal(err)
	}
	if state != "pending" || attempts != 1 || errorCode != "sink_timeout" || !available.After(time.Now()) {
		t.Fatalf("effect retry was not bounded/persisted: state=%s attempts=%d error=%s available=%s", state, attempts, errorCode, available)
	}
}

func containsRecipient(recipients []string, principal string) bool {
	for _, recipient := range recipients {
		if recipient == principal {
			return true
		}
	}
	return false
}

func forceDueReminder(t *testing.T,ctx context.Context,db *sql.DB,tenant tenancy.TenantID,caseID string){
	t.Helper();effectID:=effectUUID(t);key:=caseID+":test-case-reminder"
	_,err:=db.ExecContext(ctx,`INSERT INTO keel_meta.supplier_case_activity_effects
		(tenant_id,effect_id,case_id,effect_key,effect_type,occurrence,due_at,available_at,payload,payload_digest)
		VALUES ($1,$2,$3,$4,'case_reminder','midpoint',clock_timestamp()-interval '1 second',clock_timestamp()-interval '1 second',
		jsonb_build_object('case_id',$3::uuid::text,'occurrence','midpoint'),sha256(convert_to(jsonb_build_object('case_id',$3::uuid::text,'occurrence','midpoint')::text,'UTF8')))`,string(tenant),effectID,caseID,key)
	if err!=nil{t.Fatal(err)}
}

func assertScheduledEffects(t *testing.T,ctx context.Context,db *sql.DB,tenant tenancy.TenantID,caseID string){
	t.Helper();var count,reminders,expiry int
	if err:=db.QueryRowContext(ctx,`SELECT count(*),count(*) FILTER(WHERE effect_type='case_reminder'),count(*) FILTER(WHERE effect_type='case_expiry') FROM keel_meta.supplier_case_activity_effects WHERE tenant_id=$1 AND case_id=$2`,string(tenant),caseID).Scan(&count,&reminders,&expiry);err!=nil{t.Fatal(err)}
	if count!=3||reminders!=2||expiry!=1{t.Fatalf("case creation did not schedule deterministic reminder and expiry effects: total=%d reminders=%d expiry=%d",count,reminders,expiry)}
}

func effectUUID(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
