package webhook

import (
	"testing"
	"time"
)

func validReplayAuthorization() ReplayAuthorization {
	now := time.Now().UTC()
	return ReplayAuthorization{
		ReplayID:        "replay_12345678",
		DeliveryID:      "delivery_12345678",
		RequestedBy:     "operator@example.com",
		Reason:          "receiver asked for a replay after acknowledging a timeout",
		RequestedAt:     now,
		PriorState:      StateFailed,
		PriorAttempts:   3,
		PriorFinishedAt: now.Add(-time.Minute),
		PriorLeaseEpoch: 4,
		AuthorizedAt:    now,
		Created:         true,
	}
}

func TestReplayAuthorizationValidate(t *testing.T) {
	if err := validReplayAuthorization().Validate(); err != nil {
		t.Fatalf("valid authorization rejected: %v", err)
	}

	exhausted := validReplayAuthorization()
	exhausted.PriorState = StateExhausted
	if err := exhausted.Validate(); err != nil {
		t.Fatalf("exhausted authorization rejected: %v", err)
	}

	cases := map[string]struct {
		change func(*ReplayAuthorization)
		want   error
	}{
		"bad replay id":         {func(a *ReplayAuthorization) { a.ReplayID = "short" }, ErrInvalidReplay},
		"bad delivery id":       {func(a *ReplayAuthorization) { a.DeliveryID = "../delivery" }, ErrInvalidReplay},
		"bad actor":             {func(a *ReplayAuthorization) { a.RequestedBy = " operator" }, ErrInvalidReplay},
		"empty reason":          {func(a *ReplayAuthorization) { a.Reason = "" }, ErrInvalidReplay},
		"untrimmed reason":      {func(a *ReplayAuthorization) { a.Reason = " trailing " }, ErrInvalidReplay},
		"control in reason":     {func(a *ReplayAuthorization) { a.Reason = "line\nbreak" }, ErrInvalidReplay},
		"pending prior state":   {func(a *ReplayAuthorization) { a.PriorState = StatePending }, ErrReplayNotEligible},
		"delivered prior state": {func(a *ReplayAuthorization) { a.PriorState = StateDelivered }, ErrReplayNotEligible},
		"zero prior attempts":   {func(a *ReplayAuthorization) { a.PriorAttempts = 0 }, ErrReplayNotEligible},
		"large prior attempts":  {func(a *ReplayAuthorization) { a.PriorAttempts = 101 }, ErrReplayNotEligible},
		"negative lease epoch":  {func(a *ReplayAuthorization) { a.PriorLeaseEpoch = -1 }, ErrReplayNotEligible},
		"zero prior finished":   {func(a *ReplayAuthorization) { a.PriorFinishedAt = time.Time{} }, ErrReplayNotEligible},
		"zero requested at":     {func(a *ReplayAuthorization) { a.RequestedAt = time.Time{} }, ErrReplayNotEligible},
		"zero authorized at":    {func(a *ReplayAuthorization) { a.AuthorizedAt = time.Time{} }, ErrReplayNotEligible},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := validReplayAuthorization()
			testCase.change(&candidate)
			if err := candidate.Validate(); err != testCase.want {
				t.Fatalf("Validate() error = %v, want %v", err, testCase.want)
			}
		})
	}
}
