package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/sanskarpan/keel/internal/auth"
	"github.com/sanskarpan/keel/internal/auth/postgres"
)

func TestInviteMemberMapsOutcomes(t *testing.T) {
	actor := uuid.New()
	orgID := uuid.New()
	target := "/v1/auth/organizations/" + orgID.String() + "/invites"
	for _, tc := range []struct {
		outcome string
		err     error
		status  int
		code    string
	}{
		{"invited", nil, http.StatusCreated, ""},
		{"", postgres.ErrNotAuthorized, http.StatusForbidden, "forbidden"},
		{"", postgres.ErrConflict, http.StatusConflict, "already_member"},
	} {
		repo := orgSessionRepo(actor)
		repo.inviteOutcome, repo.inviteErr = tc.outcome, tc.err
		h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
		response := doRequest(h, http.MethodPost, target,
			map[string]string{"email": "newbie@example.test", "role": "member"}, "token")
		if response.Code != tc.status {
			t.Fatalf("%s: status=%d body=%s", tc.outcome, response.Code, response.Body.String())
		}
		if tc.code != "" && problemCode(t, response) != tc.code {
			t.Fatalf("%s: body=%s", tc.outcome, response.Body.String())
		}
		if tc.status == http.StatusCreated && (repo.invitedEmail != "newbie@example.test" || repo.invitedRole != "member") {
			t.Fatalf("invite not threaded: %+v", repo)
		}
	}
	repo := orgSessionRepo(actor)
	h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
	for _, body := range []any{
		map[string]string{"email": "not-an-email", "role": "member"},
		map[string]string{"email": "newbie@example.test", "role": "owner"},
		map[string]string{"email": "newbie@example.test", "role": "superadmin"},
		map[string]string{"email": "", "role": "member"},
	} {
		if response := doRequest(h, http.MethodPost, target, body, "token"); response.Code != http.StatusBadRequest {
			t.Fatalf("body=%v status=%d", body, response.Code)
		}
	}
}

func TestAcceptInviteMapsOutcomes(t *testing.T) {
	principal := uuid.New()
	orgID := uuid.New()
	for _, tc := range []struct {
		outcome string
		status  int
		code    string
	}{
		{"accepted", http.StatusOK, ""},
		{"unknown", http.StatusNotFound, "not_found"},
		{"duplicate", http.StatusConflict, "invite_reuse"},
		{"expired", http.StatusGone, "invite_expired"},
		{"email_mismatch", http.StatusForbidden, "forbidden"},
		{"not_active", http.StatusForbidden, "forbidden"},
		{"already_member", http.StatusConflict, "already_member"},
	} {
		repo := orgSessionRepo(principal)
		repo.acceptOutcome, repo.acceptOrg = tc.outcome, orgID
		h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
		response := doRequest(h, http.MethodPost, "/v1/auth/invites/accept",
			map[string]string{"token": "t"}, "token")
		if response.Code != tc.status {
			t.Fatalf("%s: status=%d body=%s", tc.outcome, response.Code, response.Body.String())
		}
		if tc.code != "" && problemCode(t, response) != tc.code {
			t.Fatalf("%s: body=%s", tc.outcome, response.Body.String())
		}
	}
}

func TestTransferOwnershipMapsOutcomes(t *testing.T) {
	actor := uuid.New()
	orgID := uuid.New()
	target := "/v1/auth/organizations/" + orgID.String() + "/transfer"
	newOwner := uuid.New()
	for _, tc := range []struct {
		outcome string
		err     error
		status  int
		code    string
	}{
		{"transferred", nil, http.StatusNoContent, ""},
		{"", postgres.ErrNotAuthorized, http.StatusForbidden, "forbidden"},
		{"", postgres.ErrNotFound, http.StatusNotFound, "not_found"},
	} {
		repo := orgSessionRepo(actor)
		repo.transferOutcome, repo.transferErr = tc.outcome, tc.err
		h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
		response := doRequest(h, http.MethodPost, target,
			map[string]string{"principal_id": newOwner.String()}, "token")
		if response.Code != tc.status {
			t.Fatalf("%s: status=%d body=%s", tc.outcome, response.Code, response.Body.String())
		}
		if tc.code != "" && problemCode(t, response) != tc.code {
			t.Fatalf("%s: body=%s", tc.outcome, response.Body.String())
		}
		if tc.status == http.StatusNoContent &&
			(repo.transferActor != actor || repo.transferOrg != orgID || repo.transferTarget != newOwner) {
			t.Fatalf("transfer not threaded: %+v", repo)
		}
	}
}

func TestSwitchSessionOrgMapsOutcomes(t *testing.T) {
	principal := uuid.New()
	orgID := uuid.New()
	for _, tc := range []struct {
		outcome string
		err     error
		status  int
		code    string
	}{
		{"switched", nil, http.StatusOK, ""},
		{"not_member", nil, http.StatusForbidden, "forbidden"},
		{"", postgres.ErrNotFound, http.StatusUnauthorized, "unauthenticated"},
	} {
		repo := orgSessionRepo(principal)
		repo.switchOutcome, repo.switchErr = tc.outcome, tc.err
		h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
		response := doRequest(h, http.MethodPost, "/v1/auth/sessions/switch",
			map[string]string{"org_id": orgID.String()}, "token")
		if response.Code != tc.status {
			t.Fatalf("%s: status=%d body=%s", tc.outcome, response.Code, response.Body.String())
		}
		if tc.code != "" && problemCode(t, response) != tc.code {
			t.Fatalf("%s: body=%s", tc.outcome, response.Body.String())
		}
	}
	if response := doRequest(newTestHandler(orgSessionRepo(principal), &fakeSender{}, &fakeSender{}),
		http.MethodPost, "/v1/auth/sessions/switch", map[string]string{"org_id": "nope"}, "token"); response.Code != http.StatusBadRequest {
		t.Fatalf("bad org: %d", response.Code)
	}
}

// TestHTTPInviteTransferAndSwitchAgainstPostgres drives invites, acceptance,
// transfer and session switch over HTTP against the real store.
func TestHTTPInviteTransferAndSwitchAgainstPostgres(t *testing.T) {
	identityDSN := os.Getenv("KEEL_TEST_IDENTITY_DATABASE_URL")
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if identityDSN == "" || adminDSN == "" {
		t.Skip("set identity and admin PostgreSQL URLs to run identity HTTP integration tests")
	}
	db, err := sql.Open("pgx", identityDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}
	repo, err := postgres.New(db)
	if err != nil {
		t.Fatal(err)
	}
	pepper := []byte("keel-http-pepper-keel-http-pepper-32-keel")
	verifyS, resetS := &fakeSender{}, &fakeSender{}
	h, err := New(repo, pepper, auth.TestArgonParams(), verifyS, resetS)
	if err != nil {
		t.Fatal(err)
	}

	ownerEmail := "invhttp-owner-" + uuid.NewString() + "@example.test"
	ownerToken := httpRegisterVerifyLogin(t, h, verifyS, ownerEmail, "invhttp-owner-pass-phrase")
	memberEmail := "invhttp-member-" + uuid.NewString() + "@example.test"
	memberToken := httpRegisterVerifyLogin(t, h, verifyS, memberEmail, "invhttp-member-pass-phrase")

	slug := "invhttp-" + uuid.NewString()[:8]
	response := doRequest(h, http.MethodPost, "/v1/auth/organizations",
		map[string]string{"slug": slug, "display_name": "Invite Org", "region": "home"}, ownerToken)
	if response.Code != http.StatusCreated {
		t.Fatalf("create org: %d %s", response.Code, response.Body.String())
	}
	var created struct {
		OrgID string `json:"org_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	response = doRequest(h, http.MethodPost, "/v1/auth/organizations/"+created.OrgID+"/invites",
		map[string]string{"email": memberEmail, "role": "member"}, ownerToken)
	if response.Code != http.StatusCreated {
		t.Fatalf("invite: %d %s", response.Code, response.Body.String())
	}
	if resetS.calls != 1 || resetS.token == "" || resetS.email != memberEmail {
		t.Fatalf("invite not sent: %+v", resetS)
	}
	response = doRequest(h, http.MethodPost, "/v1/auth/invites/accept",
		map[string]string{"token": resetS.token}, memberToken)
	if response.Code != http.StatusOK {
		t.Fatalf("accept: %d %s", response.Code, response.Body.String())
	}
	// The spent token cannot be reused by a third account.
	strangerToken := httpRegisterVerifyLogin(t, h, verifyS, "invhttp-stranger-"+uuid.NewString()+"@example.test", "invhttp-stranger-pass-phrase")
	response = doRequest(h, http.MethodPost, "/v1/auth/invites/accept",
		map[string]string{"token": resetS.token}, strangerToken)
	if response.Code != http.StatusConflict {
		t.Fatalf("reuse: %d %s", response.Code, response.Body.String())
	}
	// Transfer moves the seat; the demoted owner is refused afterwards.
	memberID := memberPrincipal(t, h, memberToken)
	response = doRequest(h, http.MethodPost, "/v1/auth/organizations/"+created.OrgID+"/transfer",
		map[string]string{"principal_id": memberID}, ownerToken)
	if response.Code != http.StatusNoContent {
		t.Fatalf("transfer: %d %s", response.Code, response.Body.String())
	}
	response = doRequest(h, http.MethodPost, "/v1/auth/organizations/"+created.OrgID+"/transfer",
		map[string]string{"principal_id": memberID}, ownerToken)
	if response.Code != http.StatusForbidden {
		t.Fatalf("demoted transfer: %d %s", response.Code, response.Body.String())
	}
	// The member session switches to the new org.
	response = doRequest(h, http.MethodPost, "/v1/auth/sessions/switch",
		map[string]string{"org_id": created.OrgID}, memberToken)
	if response.Code != http.StatusOK {
		t.Fatalf("switch: %d %s", response.Code, response.Body.String())
	}
	session, err := repo.SessionForToken(context.Background(), memberToken, pepper)
	if err != nil || session.OrgID != created.OrgID {
		t.Fatalf("switched session: %+v err=%v", session, err)
	}
}

func memberPrincipal(t *testing.T, h *Handler, token string) string {
	t.Helper()
	session, err := h.repo.SessionForToken(context.Background(), token, h.pepper)
	if err != nil {
		t.Fatal(err)
	}
	return session.PrincipalID
}
