package webhook

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func validReplayRequest(t *testing.T) ReplayRequest {
	t.Helper()
	return ReplayRequest{
		Tenant:      replayTenant(t),
		ReplayID:    "replay_0001",
		DeliveryID:  "delivery_0001",
		RequestedBy: "operator@example.com",
		Reason:      "receiver rejected the original delivery",
	}
}

func TestReplayRequestValidateAcceptsBoundedValues(t *testing.T) {
	base := validReplayRequest(t)
	cases := map[string]func(*ReplayRequest){
		"minimum identities": func(r *ReplayRequest) {
			r.ReplayID = "replay_1"
			r.DeliveryID = "delivery"
		},
		"maximum identities": func(r *ReplayRequest) {
			r.ReplayID = strings.Repeat("a", 64)
			r.DeliveryID = strings.Repeat("b", 64)
		},
		"hyphen and underscore identities": func(r *ReplayRequest) {
			r.ReplayID = "replay-id_0001"
			r.DeliveryID = "delivery-id_0001"
		},
		"single character actor": func(r *ReplayRequest) {
			r.RequestedBy = "o"
		},
		"maximum actor": func(r *ReplayRequest) {
			r.RequestedBy = "a" + strings.Repeat("b", 127)
		},
		"actor punctuation": func(r *ReplayRequest) {
			r.RequestedBy = "ops.team:replay-1@example.com"
		},
		"single byte reason": func(r *ReplayRequest) {
			r.Reason = "x"
		},
		"maximum reason": func(r *ReplayRequest) {
			r.Reason = strings.Repeat("r", MaxReplayReasonBytes)
		},
		"multibyte reason": func(r *ReplayRequest) {
			r.Reason = "receiver rejected the deliveré"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			request := base
			mutate(&request)
			if err := request.Validate(); err != nil {
				t.Fatalf("Validate() error = %v, want nil", err)
			}
		})
	}

	another, err := tenancy.ParseTenantID(uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	request := base
	request.Tenant = another
	if err := request.Validate(); err != nil {
		t.Fatalf("Validated request with another tenant error = %v", err)
	}
}

func TestReplayRequestValidateRejectsInvalidValues(t *testing.T) {
	cases := map[string]func(*ReplayRequest){
		"empty tenant":        func(r *ReplayRequest) { r.Tenant = "" },
		"zero tenant":         func(r *ReplayRequest) { r.Tenant = "00000000-0000-0000-0000-000000000000" },
		"malformed tenant":    func(r *ReplayRequest) { r.Tenant = "not-a-tenant" },
		"empty replay id":     func(r *ReplayRequest) { r.ReplayID = "" },
		"short replay id":     func(r *ReplayRequest) { r.ReplayID = "short" },
		"long replay id":      func(r *ReplayRequest) { r.ReplayID = strings.Repeat("a", 65) },
		"space replay id":     func(r *ReplayRequest) { r.ReplayID = "replay id" },
		"slash replay id":     func(r *ReplayRequest) { r.ReplayID = "../replay" },
		"empty delivery id":   func(r *ReplayRequest) { r.DeliveryID = "" },
		"short delivery id":   func(r *ReplayRequest) { r.DeliveryID = "short" },
		"long delivery id":    func(r *ReplayRequest) { r.DeliveryID = strings.Repeat("b", 65) },
		"space delivery id":   func(r *ReplayRequest) { r.DeliveryID = "delivery id" },
		"empty actor":         func(r *ReplayRequest) { r.RequestedBy = "" },
		"actor with space":    func(r *ReplayRequest) { r.RequestedBy = "operator name" },
		"actor leading dot":   func(r *ReplayRequest) { r.RequestedBy = ".operator" },
		"actor too long":      func(r *ReplayRequest) { r.RequestedBy = "a" + strings.Repeat("b", 128) },
		"empty reason":        func(r *ReplayRequest) { r.Reason = "" },
		"whitespace reason":   func(r *ReplayRequest) { r.Reason = "   " },
		"leading space":       func(r *ReplayRequest) { r.Reason = " rejected" },
		"trailing space":      func(r *ReplayRequest) { r.Reason = "rejected " },
		"long reason":         func(r *ReplayRequest) { r.Reason = strings.Repeat("r", MaxReplayReasonBytes+1) },
		"newline reason":      func(r *ReplayRequest) { r.Reason = "rejected\nby receiver" },
		"tab reason":          func(r *ReplayRequest) { r.Reason = "rejected\tby receiver" },
		"nul reason":          func(r *ReplayRequest) { r.Reason = "rejected\x00by receiver" },
		"delete reason":       func(r *ReplayRequest) { r.Reason = "rejected\x7fby receiver" },
		"invalid utf8 reason": func(r *ReplayRequest) { r.Reason = string([]byte{0xff, 0xfe}) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			request := validReplayRequest(t)
			mutate(&request)
			if err := request.Validate(); !errors.Is(err, ErrInvalidReplay) {
				t.Fatalf("Validate() error = %v, want ErrInvalidReplay", err)
			}
		})
	}
}

func TestValidateReplayID(t *testing.T) {
	for _, valid := range []string{"replay_1", "replay-1", "ABCDEFGH", strings.Repeat("a", 64)} {
		if err := ValidateReplayID(valid); err != nil {
			t.Fatalf("ValidateReplayID(%q) error = %v", valid, err)
		}
	}
	for _, invalid := range []string{"", "short", strings.Repeat("a", 65), "replay id", "replay/id"} {
		if err := ValidateReplayID(invalid); !errors.Is(err, ErrInvalidReplay) {
			t.Fatalf("ValidateReplayID(%q) error = %v, want ErrInvalidReplay", invalid, err)
		}
	}
}
