package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

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

// TestHTTPDirectoryLifecycleAgainstPostgres drives member/invite listing and
// revocation over HTTP against the real store.
func TestHTTPDirectoryLifecycleAgainstPostgres(t *testing.T) {
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
	ownerToken := httpRegisterVerifyLogin(t, h, verifyS, "dirhttp-owner-"+uuid.NewString()+"@example.test", "dirhttp-owner-pass-phrase")
	strangerToken := httpRegisterVerifyLogin(t, h, verifyS, "dirhttp-stranger-"+uuid.NewString()+"@example.test", "dirhttp-stranger-pass-phrase")

	slug := "dirhttp-" + uuid.NewString()[:8]
	response := doRequest(h, http.MethodPost, "/v1/auth/organizations",
		map[string]string{"slug": slug, "display_name": "Directory", "region": "home"}, ownerToken)
	if response.Code != http.StatusCreated {
		t.Fatalf("create org: %d %s", response.Code, response.Body.String())
	}
	var created struct {
		OrgID string `json:"org_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	membersTarget := "/v1/auth/organizations/" + created.OrgID + "/members"
	invitesTarget := "/v1/auth/organizations/" + created.OrgID + "/invites"
	response = doRequest(h, http.MethodGet, membersTarget, nil, ownerToken)
	if response.Code != http.StatusOK || !contains(response.Body.String(), "owner") {
		t.Fatalf("members: %d %s", response.Code, response.Body.String())
	}
	if response := doRequest(h, http.MethodGet, membersTarget, nil, strangerToken); response.Code != http.StatusForbidden {
		t.Fatalf("stranger members: %d", response.Code)
	}
	for _, email := range []string{
		"dirhttp-one-" + uuid.NewString() + "@example.test",
		"dirhttp-two-" + uuid.NewString() + "@example.test",
	} {
		response = doRequest(h, http.MethodPost, invitesTarget,
			map[string]string{"email": email, "role": "member"}, ownerToken)
		if response.Code != http.StatusCreated {
			t.Fatalf("invite %s: %d %s", email, response.Code, response.Body.String())
		}
	}
	response = doRequest(h, http.MethodGet, invitesTarget, nil, ownerToken)
	if response.Code != http.StatusOK {
		t.Fatalf("invites: %d %s", response.Code, response.Body.String())
	}
	var listed struct {
		Invites []struct {
			InviteID string `json:"invite_id"`
		} `json:"invites"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &listed); err != nil || len(listed.Invites) != 2 {
		t.Fatalf("invite list: %v %s", err, response.Body.String())
	}
	response = doRequest(h, http.MethodPost, "/v1/auth/invites/"+listed.Invites[0].InviteID+"/revoke", nil, ownerToken)
	if response.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", response.Code, response.Body.String())
	}
	response = doRequest(h, http.MethodGet, invitesTarget, nil, ownerToken)
	var remaining struct {
		Invites []struct {
			InviteID string `json:"invite_id"`
		} `json:"invites"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &remaining); err != nil || len(remaining.Invites) != 1 {
		t.Fatalf("remaining: %v %s", err, response.Body.String())
	}
	if response := doRequest(h, http.MethodPost, "/v1/auth/invites/"+listed.Invites[0].InviteID+"/revoke", nil, ownerToken); response.Code != http.StatusNotFound {
		t.Fatalf("repeat revoke: %d", response.Code)
	}
}

// TestHTTPMembershipLifecycleAgainstPostgres drives role changes, removal
// and invite reaping over HTTP against the real store.
func TestHTTPMembershipLifecycleAgainstPostgres(t *testing.T) {
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
	ownerToken := httpRegisterVerifyLogin(t, h, verifyS, "lifehttp-owner-"+uuid.NewString()+"@example.test", "lifehttp-owner-pass-phrase")
	memberEmail := "lifehttp-member-" + uuid.NewString() + "@example.test"
	memberToken := httpRegisterVerifyLogin(t, h, verifyS, memberEmail, "lifehttp-member-pass-phrase")

	slug := "lifehttp-" + uuid.NewString()[:8]
	response := doRequest(h, http.MethodPost, "/v1/auth/organizations",
		map[string]string{"slug": slug, "display_name": "Lifecycle", "region": "home"}, ownerToken)
	if response.Code != http.StatusCreated {
		t.Fatalf("create org: %d %s", response.Code, response.Body.String())
	}
	var created struct {
		OrgID string `json:"org_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	memberID := memberPrincipal(t, h, memberToken)
	roleTarget := "/v1/auth/organizations/" + created.OrgID + "/members/" + memberID + "/role"
	// Seat via invite+accept so role changes have a subject.
	response = doRequest(h, http.MethodPost, "/v1/auth/organizations/"+created.OrgID+"/invites",
		map[string]string{"email": memberEmail, "role": "member"}, ownerToken)
	if response.Code != http.StatusCreated {
		t.Fatalf("invite: %d %s", response.Code, response.Body.String())
	}
	response = doRequest(h, http.MethodPost, "/v1/auth/invites/accept",
		map[string]string{"token": resetS.token}, memberToken)
	if response.Code != http.StatusOK {
		t.Fatalf("accept: %d %s", response.Code, response.Body.String())
	}
	response = doRequest(h, http.MethodPost, roleTarget, map[string]string{"role": "admin"}, ownerToken)
	if response.Code != http.StatusOK {
		t.Fatalf("promote: %d %s", response.Code, response.Body.String())
	}
	ownerID := memberPrincipal(t, h, ownerToken)
	if response := doRequest(h, http.MethodPost,
		"/v1/auth/organizations/"+created.OrgID+"/members/"+ownerID+"/role",
		map[string]string{"role": "member"}, memberToken); response.Code != http.StatusForbidden {
		t.Fatalf("admin promote owner: %d %s", response.Code, response.Body.String())
	}
	response = doRequest(h, http.MethodPost, roleTarget, map[string]string{"role": "member"}, ownerToken)
	if response.Code != http.StatusOK {
		t.Fatalf("demote: %d %s", response.Code, response.Body.String())
	}
	removeTarget := "/v1/auth/organizations/" + created.OrgID + "/members/" + memberID + "/remove"
	if response := doRequest(h, http.MethodPost, removeTarget, nil, memberToken); response.Code != http.StatusNoContent {
		t.Fatalf("leave: %d %s", response.Code, response.Body.String())
	}
	if response := doRequest(h, http.MethodGet, "/v1/auth/organizations", nil, memberToken); !contains(response.Body.String(), `"organizations":[]`) {
		t.Fatalf("post-leave list: %d %s", response.Code, response.Body.String())
	}
	reapTarget := "/v1/auth/organizations/" + created.OrgID + "/invites/reap"
	strangerToken := httpRegisterVerifyLogin(t, h, verifyS, "lifehttp-stranger-"+uuid.NewString()+"@example.test", "lifehttp-stranger-pass-phrase")
	if response := doRequest(h, http.MethodPost, reapTarget, nil, strangerToken); response.Code != http.StatusForbidden {
		t.Fatalf("stranger reap: %d %s", response.Code, response.Body.String())
	}
	response = doRequest(h, http.MethodPost, reapTarget, nil, ownerToken)
	if response.Code != http.StatusOK || !contains(response.Body.String(), `"reaped":0`) {
		t.Fatalf("reap: %d %s", response.Code, response.Body.String())
	}
}

// TestHTTPWhoamiAgainstPostgres proves the unified chain live: a switched
// session and a bearer API key answer the same shape with their own tenant.
func TestHTTPWhoamiAgainstPostgres(t *testing.T) {
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
	ownerToken := httpRegisterVerifyLogin(t, h, verifyS, "whoami-owner-"+uuid.NewString()+"@example.test", "whoami-owner-pass-phrase")
	slug := "whoami-" + uuid.NewString()[:8]
	response := doRequest(h, http.MethodPost, "/v1/auth/organizations",
		map[string]string{"slug": slug, "display_name": "Whoami", "region": "home"}, ownerToken)
	if response.Code != http.StatusCreated {
		t.Fatalf("create org: %d %s", response.Code, response.Body.String())
	}
	var created struct {
		OrgID string `json:"org_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	response = doRequest(h, http.MethodGet, "/v1/auth/whoami", nil, ownerToken)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unswitched whoami: %d %s", response.Code, response.Body.String())
	}
	response = doRequest(h, http.MethodPost, "/v1/auth/sessions/switch",
		map[string]string{"org_id": created.OrgID}, ownerToken)
	if response.Code != http.StatusOK {
		t.Fatalf("switch: %d %s", response.Code, response.Body.String())
	}
	response = doRequest(h, http.MethodGet, "/v1/auth/whoami", nil, ownerToken)
	if response.Code != http.StatusOK || !contains(response.Body.String(), `"kind":"session"`) || !contains(response.Body.String(), created.OrgID) {
		t.Fatalf("session whoami: %d %s", response.Code, response.Body.String())
	}
	ownerID, err := uuid.Parse(memberPrincipal(t, h, ownerToken))
	if err != nil {
		t.Fatal(err)
	}
	spID := uuid.New()
	if outcome, err := repo.CreateServicePrincipal(context.Background(), spID, ownerID, uuid.MustParse(created.OrgID), "gateway"); err != nil || outcome != "created" {
		t.Fatalf("create sp: %v (outcome %q)", err, outcome)
	}
	keyID := uuid.New()
	now := time.Now().UTC()
	wire, err := repo.IssueAPIKey(context.Background(), keyID, ownerID, spID, now, time.Time{})
	if err != nil || wire == "" {
		t.Fatalf("issue: %v", err)
	}
	response = doRequest(h, http.MethodGet, "/v1/auth/whoami", nil, wire)
	if response.Code != http.StatusOK || !contains(response.Body.String(), `"kind":"api_key"`) || !contains(response.Body.String(), created.OrgID) {
		t.Fatalf("key whoami: %d %s", response.Code, response.Body.String())
	}
}
