package httpapi

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sanskarpan/keel/internal/auth"
	"github.com/sanskarpan/keel/internal/auth/postgres"
)

func directoryNow() time.Time {
	return time.Date(2026, time.November, 2, 12, 0, 0, 0, time.UTC)
}

func orgMemberRepo(actor, org uuid.UUID, role string) *fakeRepo {
	return &fakeRepo{
		session: auth.Session{
			SessionID: uuid.NewString(), PrincipalID: actor.String(),
			PrincipalState: auth.PrincipalActive,
			ExpiresAt:      directoryNow().Add(time.Hour),
		},
		orgs: []postgres.Organization{{OrgID: org, Role: role}},
	}
}

func TestListMembersRequiresMembership(t *testing.T) {
	actor := uuid.New()
	orgID := uuid.New()
	target := "/v1/auth/organizations/" + orgID.String() + "/members"
	repo := orgMemberRepo(actor, orgID, auth.OrgRoleOwner)
	repo.members = []postgres.Membership{
		{PrincipalID: actor, Role: auth.OrgRoleOwner},
		{PrincipalID: uuid.New(), Role: auth.OrgRoleMember},
	}
	h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
	response := doRequest(h, http.MethodGet, target, nil, "token")
	if response.Code != http.StatusOK || !contains(response.Body.String(), actor.String()) {
		t.Fatalf("members: %d %s", response.Code, response.Body.String())
	}
	stranger := orgSessionRepo(actor)
	h = newTestHandler(stranger, &fakeSender{}, &fakeSender{})
	if response := doRequest(h, http.MethodGet, target, nil, "token"); response.Code != http.StatusForbidden {
		t.Fatalf("stranger: %d", response.Code)
	}
	if response := doRequest(h, http.MethodGet, "/v1/auth/organizations/not-a-uuid/members", nil, "token"); response.Code != http.StatusBadRequest {
		t.Fatalf("bad org: %d", response.Code)
	}
}

func TestListInvitesAndRevoke(t *testing.T) {
	actor := uuid.New()
	orgID := uuid.New()
	inviteID := uuid.New()
	repo := orgMemberRepo(actor, orgID, auth.OrgRoleAdmin)
	repo.invites = []postgres.Invite{{
		InviteID: inviteID, EmailDigest: []byte("digest-32-bytes-long-digest-00"),
		Role: auth.OrgRoleMember,
	}}
	h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
	target := "/v1/auth/organizations/" + orgID.String() + "/invites"
	response := doRequest(h, http.MethodGet, target, nil, "token")
	if response.Code != http.StatusOK || !contains(response.Body.String(), inviteID.String()) {
		t.Fatalf("invites: %d %s", response.Code, response.Body.String())
	}
	for _, tc := range []struct {
		outcome string
		err     error
		status  int
		code    string
	}{
		{"revoked", nil, http.StatusNoContent, ""},
		{"", postgres.ErrNotAuthorized, http.StatusForbidden, "forbidden"},
		{"", postgres.ErrNotFound, http.StatusNotFound, "not_found"},
	} {
		repo.revokeInviteOutcome, repo.revokeInviteErr = tc.outcome, tc.err
		response := doRequest(h, http.MethodPost, "/v1/auth/invites/"+inviteID.String()+"/revoke", nil, "token")
		if response.Code != tc.status {
			t.Fatalf("%s: status=%d body=%s", tc.outcome, response.Code, response.Body.String())
		}
		if tc.code != "" && problemCode(t, response) != tc.code {
			t.Fatalf("%s: body=%s", tc.outcome, response.Body.String())
		}
	}
}

func TestSetMemberRoleMapsOutcomes(t *testing.T) {
	actor := uuid.New()
	orgID := uuid.New()
	target := "/v1/auth/organizations/" + orgID.String() + "/members/" + uuid.NewString() + "/role"
	for _, tc := range []struct {
		outcome string
		err     error
		status  int
		code    string
	}{
		{"changed", nil, http.StatusOK, ""},
		{"unchanged", nil, http.StatusOK, ""},
		{"", postgres.ErrNotAuthorized, http.StatusForbidden, "forbidden"},
		{"", postgres.ErrNotFound, http.StatusNotFound, "not_found"},
		{"", postgres.ErrConflict, http.StatusConflict, "owner_immutable"},
	} {
		repo := orgMemberRepo(actor, orgID, auth.OrgRoleOwner)
		repo.roleOutcome, repo.roleErr = tc.outcome, tc.err
		h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
		response := doRequest(h, http.MethodPost, target, map[string]string{"role": "admin"}, "token")
		if response.Code != tc.status {
			t.Fatalf("%s: status=%d body=%s", tc.outcome, response.Code, response.Body.String())
		}
		if tc.code != "" && problemCode(t, response) != tc.code {
			t.Fatalf("%s: body=%s", tc.outcome, response.Body.String())
		}
	}
	repo := orgMemberRepo(actor, orgID, auth.OrgRoleOwner)
	h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
	for _, body := range []any{
		map[string]string{"role": "owner"},
		map[string]string{"role": "superadmin"},
		map[string]string{"role": ""},
	} {
		if response := doRequest(h, http.MethodPost, target, body, "token"); response.Code != http.StatusBadRequest {
			t.Fatalf("body=%v status=%d", body, response.Code)
		}
	}
}

func TestRemoveMemberAndReapMapsOutcomes(t *testing.T) {
	actor := uuid.New()
	orgID := uuid.New()
	memberID := uuid.New().String()
	for _, tc := range []struct {
		name   string
		target string
		body   any
		setup  func(r *fakeRepo)
		status int
		code   string
	}{
		{"removed", "/v1/auth/organizations/" + orgID.String() + "/members/" + memberID + "/remove", nil,
			func(r *fakeRepo) { r.removeOutcome = "removed" }, http.StatusNoContent, ""},
		{"remove forbidden", "/v1/auth/organizations/" + orgID.String() + "/members/" + memberID + "/remove", nil,
			func(r *fakeRepo) { r.removeErr = postgres.ErrNotAuthorized }, http.StatusForbidden, "forbidden"},
		{"remove missing", "/v1/auth/organizations/" + orgID.String() + "/members/" + memberID + "/remove", nil,
			func(r *fakeRepo) { r.removeErr = postgres.ErrNotFound }, http.StatusNotFound, "not_found"},
		{"remove owner", "/v1/auth/organizations/" + orgID.String() + "/members/" + memberID + "/remove", nil,
			func(r *fakeRepo) { r.removeErr = postgres.ErrConflict }, http.StatusConflict, "owner_immutable"},
		{"reaped", "/v1/auth/organizations/" + orgID.String() + "/invites/reap", nil,
			func(r *fakeRepo) { r.reaped = 2 }, http.StatusOK, ""},
		{"reap forbidden", "/v1/auth/organizations/" + orgID.String() + "/invites/reap", nil,
			func(r *fakeRepo) { r.reapErr = postgres.ErrNotAuthorized }, http.StatusForbidden, "forbidden"},
	} {
		repo := orgMemberRepo(actor, orgID, auth.OrgRoleOwner)
		tc.setup(repo)
		h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
		response := doRequest(h, http.MethodPost, tc.target, tc.body, "token")
		if response.Code != tc.status {
			t.Fatalf("%s: status=%d body=%s", tc.name, response.Code, response.Body.String())
		}
		if tc.code != "" && problemCode(t, response) != tc.code {
			t.Fatalf("%s: body=%s", tc.name, response.Body.String())
		}
	}
}
