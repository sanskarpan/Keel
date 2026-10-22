package webhook

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

type fakeResolver struct {
	answers map[string][]net.IPAddr
	err     error
	calls   int
}

func (f *fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	addresses, ok := f.answers[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	return addresses, nil
}

func publicAnswer(address string) []net.IPAddr {
	return []net.IPAddr{{IP: net.ParseIP(address)}}
}

func newTestEgress(t *testing.T, policy EgressPolicy, resolver Resolver) *Egress {
	t.Helper()
	egress, err := NewEgress(policy, resolver)
	if err != nil {
		t.Fatalf("NewEgress: %v", err)
	}
	return egress
}

func TestNewEgressPolicyValidation(t *testing.T) {
	t.Parallel()

	invalid := []EgressPolicy{
		{MaxRedirects: -1},
		{Timeout: -time.Second},
		{Ports: []int{0}},
		{Ports: []int{70000}},
	}
	for _, policy := range invalid {
		if _, err := NewEgress(policy, &fakeResolver{}); !errors.Is(err, ErrEgressDenied) {
			t.Fatalf("policy %+v: expected ErrEgressDenied, got %v", policy, err)
		}
	}

	egress := newTestEgress(t, EgressPolicy{}, nil)
	transport, ok := egress.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected an *http.Transport, got %T", egress.Client().Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("egress must not inherit environment proxies")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion < 0x0303 {
		t.Fatalf("egress must require TLS 1.2 or newer, got %+v", transport.TLSClientConfig)
	}
	if egress.Client().Timeout != defaultEgressTimeout {
		t.Fatalf("expected the default timeout, got %s", egress.Client().Timeout)
	}
}

func TestValidateURL(t *testing.T) {
	t.Parallel()

	egress := newTestEgress(t, EgressPolicy{}, &fakeResolver{})
	withPort := newTestEgress(t, EgressPolicy{Ports: []int{443, 8443}}, &fakeResolver{})

	cases := []struct {
		name    string
		egress  *Egress
		raw     string
		wantErr bool
	}{
		{name: "https hostname", raw: "https://hooks.example.com/keel/events"},
		{name: "https hostname with allowed port", egress: withPort, raw: "https://hooks.example.com:8443/keel"},
		{name: "https literal public ip", raw: "https://93.184.216.34/keel"},
		{name: "https ipv6 literal public", raw: "https://[2001:4860:4860::8888]/keel"},
		{name: "http", raw: "http://hooks.example.com/keel", wantErr: true},
		{name: "no scheme", raw: "hooks.example.com/keel", wantErr: true},
		{name: "userinfo", raw: "https://user:pass@hooks.example.com/keel", wantErr: true},
		{name: "no host", raw: "https:///keel", wantErr: true},
		{name: "disallowed port", raw: "https://hooks.example.com:8443/keel", wantErr: true},
		{name: "odd port", raw: "https://hooks.example.com:99999/keel", wantErr: true},
		{name: "single label", raw: "https://localhost/keel", wantErr: true},
		{name: "trailing dot", raw: "https://hooks.example.com./keel", wantErr: true},
		{name: "leading dot", raw: "https://.example.com/keel", wantErr: true},
		{name: "empty label", raw: "https://hooks..example.com/keel", wantErr: true},
		{name: "bad label", raw: "https://-hooks.example.com/keel", wantErr: true},
		{name: "underscore label", raw: "https://hook_s.example.com/keel", wantErr: true},
		{name: "zone", raw: "https://[fe80::1%25eth0]/keel", wantErr: true},
		{name: "loopback literal", raw: "https://127.0.0.1/keel", wantErr: true},
		{name: "private literal", raw: "https://10.1.2.3/keel", wantErr: true},
		{name: "metadata literal", raw: "https://169.254.169.254/latest/meta-data", wantErr: true},
		{name: "cgnat literal", raw: "https://100.64.0.9/keel", wantErr: true},
		{name: "ipv6 loopback literal", raw: "https://[::1]/keel", wantErr: true},
		{name: "ipv6 unique local literal", raw: "https://[fd00::1]/keel", wantErr: true},
		{name: "mapped private literal", raw: "https://[::ffff:10.0.0.1]/keel", wantErr: true},
	}

	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			target, err := url.Parse(testCase.raw)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", testCase.raw, err)
			}
			subject := testCase.egress
			if subject == nil {
				subject = egress
			}
			err = subject.ValidateURL(target)
			if testCase.wantErr {
				if !errors.Is(err, ErrEgressDenied) {
					t.Fatalf("expected ErrEgressDenied, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateURL: %v", err)
			}
		})
	}

	if err := egress.ValidateURL(nil); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("expected ErrEgressDenied for a nil URL, got %v", err)
	}
	var nilEgress *Egress
	if err := nilEgress.ValidateURL(&url.URL{Scheme: "https", Host: "example.com"}); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("expected ErrEgressDenied for a nil client, got %v", err)
	}
}

func TestIsPublicIP(t *testing.T) {
	t.Parallel()

	cases := []struct {
		address string
		public  bool
	}{
		{address: "8.8.8.8", public: true},
		{address: "93.184.216.34", public: true},
		{address: "172.15.255.255", public: true},
		{address: "100.128.0.1", public: true},
		{address: "2001:4860:4860::8888", public: true},
		{address: "::ffff:8.8.8.8", public: true},
		{address: "0.0.0.0"},
		{address: "10.0.0.1"},
		{address: "127.0.0.1"},
		{address: "169.254.169.254"},
		{address: "172.16.0.1"},
		{address: "192.168.1.1"},
		{address: "100.64.0.1"},
		{address: "100.127.255.255"},
		{address: "192.0.2.1"},
		{address: "198.18.0.1"},
		{address: "198.51.100.1"},
		{address: "203.0.113.1"},
		{address: "224.0.0.1"},
		{address: "240.0.0.1"},
		{address: "::"},
		{address: "::1"},
		{address: "fe80::1"},
		{address: "fd00::1"},
		{address: "ff02::1"},
		{address: "2001:db8::1"},
		{address: "::ffff:10.0.0.1"},
		{address: "::ffff:127.0.0.1"},
		{address: "64:ff9b:1::1"},
		{address: "100::1"},
	}

	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.address, func(t *testing.T) {
			t.Parallel()
			ip := net.ParseIP(testCase.address)
			if ip == nil {
				t.Fatalf("unparseable address %q", testCase.address)
			}
			if got := isPublicIP(ip); got != testCase.public {
				t.Fatalf("isPublicIP(%s) = %t, want %t", testCase.address, got, testCase.public)
			}
		})
	}

	if isPublicIP(nil) {
		t.Fatal("a nil IP must not be public")
	}
}

func TestDialContextFailsClosedOnMixedAnswers(t *testing.T) {
	t.Parallel()

	resolver := &fakeResolver{answers: map[string][]net.IPAddr{
		"rebind.example.com": {{IP: net.ParseIP("93.184.216.34")}, {IP: net.ParseIP("10.0.0.7")}},
	}}
	egress := newTestEgress(t, EgressPolicy{}, resolver)
	dialed := false
	egress.dial = func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("unexpected dial")
	}

	if _, err := egress.DialContext(context.Background(), "tcp", "rebind.example.com:443"); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("expected ErrEgressDenied, got %v", err)
	}
	if dialed {
		t.Fatal("a hostname with any non-public answer must not be dialed")
	}
	if resolver.calls != 1 {
		t.Fatalf("expected one resolution, got %d", resolver.calls)
	}
}

func TestDialContextPinsResolvedAddress(t *testing.T) {
	t.Parallel()

	resolver := &fakeResolver{answers: map[string][]net.IPAddr{
		"hooks.example.com": publicAnswer("93.184.216.34"),
	}}
	egress := newTestEgress(t, EgressPolicy{}, resolver)
	var dialedAddress string
	egress.dial = func(_ context.Context, network, address string) (net.Conn, error) {
		dialedAddress = network + " " + address
		return nil, errors.New("stop before connecting")
	}

	if _, err := egress.DialContext(context.Background(), "tcp", "hooks.example.com:443"); err == nil {
		t.Fatal("expected the fake dial error")
	}
	if dialedAddress != "tcp 93.184.216.34:443" {
		t.Fatalf("expected the dial to be pinned to the vetted address, got %q", dialedAddress)
	}
}

func TestDialContextResolvesOnEveryDial(t *testing.T) {
	t.Parallel()

	resolver := &fakeResolver{answers: map[string][]net.IPAddr{
		"rotate.example.com": publicAnswer("93.184.216.34"),
	}}
	egress := newTestEgress(t, EgressPolicy{}, resolver)
	egress.dial = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("stop before connecting")
	}
	if _, err := egress.DialContext(context.Background(), "tcp", "rotate.example.com:443"); err == nil {
		t.Fatal("expected the fake dial error")
	}

	resolver.answers["rotate.example.com"] = publicAnswer("10.0.0.7")
	if _, err := egress.DialContext(context.Background(), "tcp", "rotate.example.com:443"); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("expected a re-resolution to deny the private answer, got %v", err)
	}
	if resolver.calls != 2 {
		t.Fatalf("expected two resolutions, got %d", resolver.calls)
	}
}

func TestDialContextLiteralAddresses(t *testing.T) {
	t.Parallel()

	egress := newTestEgress(t, EgressPolicy{}, &fakeResolver{})
	var dialedAddress string
	egress.dial = func(_ context.Context, _, address string) (net.Conn, error) {
		dialedAddress = address
		return nil, errors.New("stop before connecting")
	}

	if _, err := egress.DialContext(context.Background(), "tcp", "93.184.216.34:443"); err == nil {
		t.Fatal("expected the fake dial error")
	}
	if dialedAddress != "93.184.216.34:443" {
		t.Fatalf("unexpected literal dial %q", dialedAddress)
	}

	for _, address := range []string{
		"127.0.0.1:443",
		"10.0.0.1:443",
		"169.254.169.254:443",
		"[::1]:443",
		"[::ffff:127.0.0.1]:443",
		"93.184.216.34:8443",
		"93.184.216.34",
		"",
	} {
		if _, err := egress.DialContext(context.Background(), "tcp", address); !errors.Is(err, ErrEgressDenied) {
			t.Fatalf("address %q: expected ErrEgressDenied, got %v", address, err)
		}
	}
}

func TestDialContextResolverFailures(t *testing.T) {
	t.Parallel()

	resolver := &fakeResolver{err: errors.New("dns timeout")}
	egress := newTestEgress(t, EgressPolicy{}, resolver)
	if _, err := egress.DialContext(context.Background(), "tcp", "hooks.example.com:443"); !errors.Is(err, ErrEgressUnavailable) {
		t.Fatalf("expected ErrEgressUnavailable, got %v", err)
	}

	resolver.err = nil
	resolver.answers = map[string][]net.IPAddr{"hooks.example.com": {}}
	if _, err := egress.DialContext(context.Background(), "tcp", "hooks.example.com:443"); !errors.Is(err, ErrEgressUnavailable) {
		t.Fatalf("expected ErrEgressUnavailable for an empty answer, got %v", err)
	}

	resolver.answers = map[string][]net.IPAddr{
		"zoned.example.com": {{IP: net.ParseIP("93.184.216.34"), Zone: "eth0"}},
	}
	if _, err := egress.DialContext(context.Background(), "tcp", "zoned.example.com:443"); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("expected ErrEgressDenied for a zoned answer, got %v", err)
	}
}

func TestClientBlocksPrivateLiteralNetwork(t *testing.T) {
	t.Parallel()

	egress := newTestEgress(t, EgressPolicy{}, &fakeResolver{})
	if _, err := egress.Client().Get("https://127.0.0.1/keel"); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("expected the client to deny a loopback literal, got %v", err)
	}
	if _, err := egress.Client().Get("http://127.0.0.1/keel"); err == nil {
		t.Fatal("expected an error for a non-TLS request")
	}
}

func TestClientRedirectPolicy(t *testing.T) {
	t.Parallel()

	egress := newTestEgress(t, EgressPolicy{}, &fakeResolver{})
	client := egress.Client()
	origin, err := http.NewRequest(http.MethodGet, "https://hooks.example.com/keel", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	public, err := http.NewRequest(http.MethodGet, "https://other.example.com/keel", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if err := client.CheckRedirect(public, []*http.Request{origin}); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("expected the default policy to refuse redirects, got %v", err)
	}

	one := newTestEgress(t, EgressPolicy{MaxRedirects: 1}, &fakeResolver{})
	if err := one.Client().CheckRedirect(public, []*http.Request{origin}); err != nil {
		t.Fatalf("expected one allowed redirect, got %v", err)
	}
	private, err := http.NewRequest(http.MethodGet, "https://10.0.0.7/keel", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if err := one.Client().CheckRedirect(private, []*http.Request{origin}); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("expected a redirect to a private literal to be denied, got %v", err)
	}
	if err := one.Client().CheckRedirect(public, []*http.Request{origin, public}); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("expected the redirect budget to be enforced, got %v", err)
	}
}
