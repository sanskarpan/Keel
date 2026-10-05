// Package tools contains fixed, read-only agent query tools. It exposes no SQL
// or generic query surface.
package tools

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"time"

	"github.com/google/uuid"
)

const (
	GetOrderSummaryName = "get_order_summary"
	maxToolInputBytes   = 1024
)

var (
	ErrToolRejected     = errors.New("agent query rejected")
	ErrToolUnavailable  = errors.New("agent query unavailable")
	ErrToolNotFound     = errors.New("agent query resource not found")
	orderSummarySQL     = `SELECT status, version, updated_at FROM keel_meta.agent_order_summary WHERE order_id = $1`
	principalRefPattern = regexp.MustCompile(`^principal:[A-Za-z0-9._~-]{1,120}$`)
)

// Principal contains validated identity claims supplied by trusted server
// authentication middleware. Never derive claims from model/tool input or
// tenant-supplied request fields. Its constructor validates shape, not identity.
type Principal struct {
	ref      string
	tenantID string
}

func NewPrincipalFromVerifiedAuth(principalRef, tenantID string) (Principal, error) {
	if !principalRefPattern.MatchString(principalRef) {
		return Principal{}, ErrToolRejected
	}
	parsed, err := uuid.Parse(tenantID)
	if err != nil || parsed.String() != tenantID {
		return Principal{}, ErrToolRejected
	}
	return Principal{ref: principalRef, tenantID: tenantID}, nil
}

type OrderSummary struct {
	Status    string    `json:"status"`
	Version   int64     `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

type OrderAuthorizer interface {
	CanReadOrder(context.Context, string, string, uuid.UUID) (bool, error)
}

// BoundOrderReader is bound at construction to one configured tenant agent
// login. Its DB role's session_user mapping is the final database tenant fence.
type BoundOrderReader interface {
	TenantID() string
	ReadOrderSummary(context.Context, uuid.UUID) (OrderSummary, error)
}

type OrderSummaryBroker struct {
	tenantID   string
	authorizer OrderAuthorizer
	reader     BoundOrderReader
}

func NewOrderSummaryBroker(tenantID string, authorizer OrderAuthorizer, reader BoundOrderReader) (*OrderSummaryBroker, error) {
	parsed, err := uuid.Parse(tenantID)
	if err != nil || parsed.String() != tenantID || isNilDependency(authorizer) || isNilDependency(reader) || reader.TenantID() != tenantID {
		return nil, ErrToolUnavailable
	}
	return &OrderSummaryBroker{tenantID: tenantID, authorizer: authorizer, reader: reader}, nil
}

func isNilDependency(value any) bool {
	if value == nil {
		return true
	}
	ref := reflect.ValueOf(value)
	switch ref.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return ref.IsNil()
	default:
		return false
	}
}

// Invoke accepts exactly one registered tool name and a strictly decoded,
// bounded order identifier. Principal identity comes from trusted middleware.
func (b *OrderSummaryBroker) Invoke(ctx context.Context, principal Principal, toolName string, input []byte) (OrderSummary, error) {
	if b == nil || b.authorizer == nil || b.reader == nil || ctx == nil || toolName != GetOrderSummaryName ||
		principal.ref == "" || principal.tenantID != b.tenantID || b.reader.TenantID() != b.tenantID {
		return OrderSummary{}, ErrToolRejected
	}
	orderID, err := parseOrderID(input)
	if err != nil {
		return OrderSummary{}, ErrToolRejected
	}
	allowed, err := b.authorizer.CanReadOrder(ctx, principal.ref, principal.tenantID, orderID)
	if err != nil {
		return OrderSummary{}, ErrToolUnavailable
	}
	if !allowed {
		// Match a missing RLS-hidden row so tool callers cannot probe resource IDs.
		return OrderSummary{}, ErrToolNotFound
	}
	summary, err := b.reader.ReadOrderSummary(ctx, orderID)
	if errors.Is(err, ErrToolNotFound) {
		return OrderSummary{}, ErrToolNotFound
	}
	if err != nil {
		return OrderSummary{}, ErrToolUnavailable
	}
	return summary, nil
}

func parseOrderID(input []byte) (uuid.UUID, error) {
	if len(input) == 0 || len(input) > maxToolInputBytes {
		return uuid.Nil, ErrToolRejected
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return uuid.Nil, ErrToolRejected
	}
	seen := false
	var value string
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return uuid.Nil, ErrToolRejected
		}
		key, ok := token.(string)
		if !ok || key != "order_id" || seen {
			return uuid.Nil, ErrToolRejected
		}
		if err := decoder.Decode(&value); err != nil {
			return uuid.Nil, ErrToolRejected
		}
		seen = true
	}
	if _, err := decoder.Token(); err != nil || !seen {
		return uuid.Nil, ErrToolRejected
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return uuid.Nil, ErrToolRejected
	}
	parsed, err := uuid.Parse(value)
	if err != nil || parsed.String() != value {
		return uuid.Nil, ErrToolRejected
	}
	return parsed, nil
}

type PostgresOrderSummaryReader struct {
	tenantID string
	db       *sql.DB
}

func NewPostgresOrderSummaryReader(tenantID string, db *sql.DB) (*PostgresOrderSummaryReader, error) {
	parsed, err := uuid.Parse(tenantID)
	if err != nil || parsed.String() != tenantID || db == nil {
		return nil, ErrToolUnavailable
	}
	return &PostgresOrderSummaryReader{tenantID: tenantID, db: db}, nil
}

func (r *PostgresOrderSummaryReader) TenantID() string {
	if r == nil {
		return ""
	}
	return r.tenantID
}

func (r *PostgresOrderSummaryReader) ReadOrderSummary(ctx context.Context, orderID uuid.UUID) (OrderSummary, error) {
	if r == nil || r.db == nil || ctx == nil || orderID == uuid.Nil {
		return OrderSummary{}, ErrToolUnavailable
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return OrderSummary{}, ErrToolUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	var sessionUser, boundTenant string
	var agentRole bool
	if err := tx.QueryRowContext(ctx, `SELECT session_user::text, keel_private.current_tenant_id()::text, pg_catalog.pg_has_role(session_user,'keel_agent','MEMBER')`).Scan(&sessionUser, &boundTenant, &agentRole); err != nil || sessionUser == "" || boundTenant != r.tenantID || !agentRole {
		return OrderSummary{}, ErrToolUnavailable
	}
	var result OrderSummary
	err = tx.QueryRowContext(ctx, orderSummarySQL, orderID.String()).Scan(&result.Status, &result.Version, &result.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return OrderSummary{}, ErrToolNotFound
	}
	if err != nil {
		return OrderSummary{}, ErrToolUnavailable
	}
	if err := tx.Commit(); err != nil {
		return OrderSummary{}, ErrToolUnavailable
	}
	return result, nil
}
