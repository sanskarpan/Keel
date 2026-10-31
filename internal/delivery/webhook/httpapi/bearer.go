package httpapi

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

var (
	bearerNamePattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	bearerTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)
)

// MinBearerTokenBytes is documentation for the token-length floor enforced by the pattern:
// 32 URL-safe characters carry at least 192 bits of entropy when generated randomly.
const MinBearerTokenLength = 32

// TokenGrant binds one opaque bearer token to one tenant with scoped operator permissions.
// The name is operator-assigned and appears in audit actor references; the token itself never
// appears in logs, errors or responses.
type TokenGrant struct {
	Tenant   tenancy.TenantID
	Name     string
	Token    string
	Replay   bool
	Policies bool
}

// ParseTokenGrants parses comma-separated `tenant:name:token[:scopes]` entries, where scopes is
// `+`-separated `replay`/`policies` and defaults to both when absent. Duplicate names, duplicate
// tokens, unknown scopes and malformed entries are rejected.
func ParseTokenGrants(raw string) ([]TokenGrant, error) {
	var grants []TokenGrant
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("operator token grants are required")
	}
	names := make(map[string]struct{})
	for _, entry := range strings.Split(raw, ",") {
		parts := strings.Split(strings.TrimSpace(entry), ":")
		if len(parts) != 3 && len(parts) != 4 {
			return nil, errors.New("operator token grant shape is invalid")
		}
		tenant, err := tenancy.ParseTenantID(parts[0])
		if err != nil || string(tenant) == "" || string(tenant) == "00000000-0000-0000-0000-000000000000" {
			return nil, errors.New("operator token grant tenant is invalid")
		}
		if !bearerNamePattern.MatchString(parts[1]) {
			return nil, errors.New("operator token grant name is invalid")
		}
		if _, duplicate := names[parts[1]]; duplicate {
			return nil, errors.New("operator token grant name is duplicated")
		}
		if !bearerTokenPattern.MatchString(parts[2]) {
			return nil, errors.New("operator token grant token is invalid")
		}
		grant := TokenGrant{Tenant: tenant, Name: parts[1], Token: parts[2], Replay: true, Policies: true}
		if len(parts) == 4 {
			grant.Replay, grant.Policies = false, false
			if strings.TrimSpace(parts[3]) == "" {
				return nil, errors.New("operator token grant scopes are invalid")
			}
			for _, scope := range strings.Split(parts[3], "+") {
				switch scope {
				case "replay":
					grant.Replay = true
				case "policies":
					grant.Policies = true
				default:
					return nil, errors.New("operator token grant scopes are invalid")
				}
			}
		}
		for _, existing := range grants {
			if subtle.ConstantTimeCompare([]byte(existing.Token), []byte(grant.Token)) == 1 {
				return nil, errors.New("operator token grant token is duplicated")
			}
		}
		names[parts[1]] = struct{}{}
		grants = append(grants, grant)
	}
	return grants, nil
}

// BearerAuth resolves bearer principals and enforces their scopes. It implements both
// PrincipalResolver and Authorizer so one configured value wires the whole handler. The zero
// value denies everything.
type BearerAuth struct {
	grants []TokenGrant
}

// NewBearerAuth requires at least one grant; a handler without credentials must not exist.
func NewBearerAuth(grants []TokenGrant) (*BearerAuth, error) {
	if len(grants) == 0 {
		return nil, errors.New("operator bearer grants are required")
	}
	return &BearerAuth{grants: append([]TokenGrant(nil), grants...)}, nil
}

// Resolve authenticates `Authorization: Bearer <token>` with a constant-time comparison. The
// actor reference names the grant, never the token.
func (b *BearerAuth) Resolve(_ context.Context, r *http.Request) (Principal, bool) {
	if b == nil || r == nil {
		return Principal{}, false
	}
	header := r.Header.Get("Authorization")
	if header == "" || len(header) > 256 {
		return Principal{}, false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return Principal{}, false
	}
	presented := strings.TrimPrefix(header, prefix)
	if presented != strings.TrimSpace(presented) {
		return Principal{}, false
	}
	if !bearerTokenPattern.MatchString(presented) {
		return Principal{}, false
	}
	for _, grant := range b.grants {
		if subtle.ConstantTimeCompare([]byte(grant.Token), []byte(presented)) == 1 {
			return Principal{TenantID: grant.Tenant, ActorRef: "bearer:" + grant.Name}, true
		}
	}
	return Principal{}, false
}

// CanReplayWebhooks reports whether the principal's grant carries the replay scope.
func (b *BearerAuth) CanReplayWebhooks(_ context.Context, principal Principal) bool {
	return b.scope(principal, true)
}

// CanManageWebhookPolicies reports whether the principal's grant carries the policy scope.
func (b *BearerAuth) CanManageWebhookPolicies(_ context.Context, principal Principal) bool {
	return b.scope(principal, false)
}

func (b *BearerAuth) scope(principal Principal, replay bool) bool {
	if b == nil {
		return false
	}
	name, ok := strings.CutPrefix(principal.ActorRef, "bearer:")
	if !ok || name == "" {
		return false
	}
	for _, grant := range b.grants {
		if grant.Name == name && grant.Tenant == principal.TenantID {
			if replay {
				return grant.Replay
			}
			return grant.Policies
		}
	}
	return false
}

var (
	_ PrincipalResolver = (*BearerAuth)(nil)
	_ Authorizer        = (*BearerAuth)(nil)
)
