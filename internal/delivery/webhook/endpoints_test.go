package webhook

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateEndpointURL(t *testing.T) {
	cases := map[string]struct {
		raw     string
		wantErr bool
	}{
		"https path":       {raw: "https://example.com/webhooks/orders"},
		"explicit 443":     {raw: "https://hooks.example.com:443/orders?token=abc"},
		"public literal":   {raw: "https://93.184.216.34/hook"},
		"http scheme":      {raw: "http://example.com/hook", wantErr: true},
		"userinfo":         {raw: "https://user:secret@example.com/hook", wantErr: true},
		"fragment":         {raw: "https://example.com/hook#part", wantErr: true},
		"loopback name":    {raw: "https://localhost/hook", wantErr: true},
		"loopback literal": {raw: "https://127.0.0.1/hook", wantErr: true},
		"private literal":  {raw: "https://10.0.0.1/hook", wantErr: true},
		"metadata literal": {raw: "https://169.254.169.254/latest", wantErr: true},
		"ipv6 loopback":    {raw: "https://[::1]/hook", wantErr: true},
		"unallowed port":   {raw: "https://example.com:8443/hook", wantErr: true},
		"no host":          {raw: "https:///hook", wantErr: true},
		"empty":            {raw: "", wantErr: true},
		"space":            {raw: "https://example.com/a b", wantErr: true},
		"control":          {raw: "https://example.com/a\x00b", wantErr: true},
		"too long":         {raw: "https://example.com/" + strings.Repeat("a", MaxEndpointURLLength), wantErr: true},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			err := ValidateEndpointURL(testCase.raw)
			if (err != nil) != testCase.wantErr {
				t.Fatalf("ValidateEndpointURL(%q) error = %v, want error %t", testCase.raw, err, testCase.wantErr)
			}
			if err != nil && !errors.Is(err, ErrInvalidEndpoint) {
				t.Fatalf("ValidateEndpointURL(%q) error = %v, want ErrInvalidEndpoint", testCase.raw, err)
			}
		})
	}
}

func validRegistration() EndpointRegistration {
	return EndpointRegistration{
		ID:                  "endpoint_01",
		URL:                 "https://example.com/webhooks/orders",
		KeyID:               "key_2026",
		SubscriptionVersion: 1,
	}
}

func TestEndpointRegistrationValidate(t *testing.T) {
	if err := validRegistration().Validate(); err != nil {
		t.Fatalf("valid registration rejected: %v", err)
	}
	cases := map[string]func(*EndpointRegistration){
		"empty id":        func(r *EndpointRegistration) { r.ID = "" },
		"short id":        func(r *EndpointRegistration) { r.ID = "short" },
		"id punctuation":  func(r *EndpointRegistration) { r.ID = "endpoint.01" },
		"short key":       func(r *EndpointRegistration) { r.KeyID = "abc" },
		"key punctuation": func(r *EndpointRegistration) { r.KeyID = "key.2026" },
		"zero version":    func(r *EndpointRegistration) { r.SubscriptionVersion = 0 },
		"version cap":     func(r *EndpointRegistration) { r.SubscriptionVersion = MaxSubscriptionVersion + 1 },
		"http url":        func(r *EndpointRegistration) { r.URL = "http://example.com/hook" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			registration := validRegistration()
			mutate(&registration)
			if err := registration.Validate(); !errors.Is(err, ErrInvalidEndpoint) {
				t.Fatalf("Validate() error = %v, want ErrInvalidEndpoint", err)
			}
		})
	}
}

func TestValidateEndpointID(t *testing.T) {
	for _, valid := range []string{"endpoint_01", "ep-2026-0001", "01234567"} {
		if err := ValidateEndpointID(valid); err != nil {
			t.Fatalf("ValidateEndpointID(%q) error = %v", valid, err)
		}
	}
	for _, invalid := range []string{"", "short", "endpoint.01", "../endpoint", strings.Repeat("a", 65)} {
		if err := ValidateEndpointID(invalid); !errors.Is(err, ErrInvalidEndpoint) {
			t.Fatalf("ValidateEndpointID(%q) error = %v, want ErrInvalidEndpoint", invalid, err)
		}
	}
}

func TestEndpointRegistrationRoundTrip(t *testing.T) {
	registration := validRegistration()
	endpoint := Endpoint{
		ID:                  registration.ID,
		URL:                 registration.URL,
		KeyID:               registration.KeyID,
		SubscriptionVersion: registration.SubscriptionVersion,
		Status:              EndpointActive,
		Version:             3,
	}
	if got := endpoint.Registration(); got != registration {
		t.Fatalf("Registration() = %+v, want %+v", got, registration)
	}
}
