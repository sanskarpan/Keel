package webhook

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrEgressDenied means a destination is not allowed: wrong scheme, credentials in the URL,
	// a disallowed port, or an address that is loopback, private, link-local, reserved or
	// otherwise not publicly routable.
	ErrEgressDenied = errors.New("webhook egress destination is not allowed")
	// ErrEgressUnavailable means the destination could not be resolved. It is a transient failure,
	// not a policy decision, and must not be retried against another resolver or host alias.
	ErrEgressUnavailable = errors.New("webhook egress destination could not be resolved")
)

const (
	defaultEgressPort    = 443
	defaultEgressTimeout = 15 * time.Second
)

var hostnamePattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

var (
	deniedIPv4 = parseDeniedNetworks(
		"0.0.0.0/8",
		"100.64.0.0/10",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"192.88.99.0/24",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"240.0.0.0/4",
	)
	deniedIPv6 = parseDeniedNetworks(
		"64:ff9b:1::/48",
		"100::/64",
		"2001::/23",
		"2001:db8::/32",
	)
)

func parseDeniedNetworks(cidrs ...string) []*net.IPNet {
	networks := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("webhook egress denied network is invalid: " + cidr)
		}
		networks = append(networks, network)
	}
	return networks
}

// Resolver resolves a destination host. Production uses the process resolver; tests inject a
// deterministic one. A custom resolver must not bypass the address vetting in DialContext.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// EgressPolicy bounds an egress client. A zero value selects the default port 443, no redirects
// and a 15-second overall timeout.
type EgressPolicy struct {
	Ports        []int
	MaxRedirects int
	Timeout      time.Duration
}

// Egress is an HTTP client that resolves, vets and pins every destination address. It is immutable
// after construction, so one value can be shared by a delivery worker.
type Egress struct {
	policy   EgressPolicy
	resolver Resolver
	client   *http.Client
	dial     DialFunc
}

// DialFunc dials an already-vetted network address.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// NewEgress builds the egress client. A nil resolver uses the process resolver. A policy with no
// ports allows only 443, and no redirect is followed by default.
func NewEgress(policy EgressPolicy, resolver Resolver) (*Egress, error) {
	if policy.MaxRedirects < 0 {
		return nil, ErrEgressDenied
	}
	if policy.Timeout < 0 {
		return nil, ErrEgressDenied
	}
	if len(policy.Ports) == 0 {
		policy.Ports = []int{defaultEgressPort}
	}
	for _, port := range policy.Ports {
		if port < 1 || port > 65535 {
			return nil, ErrEgressDenied
		}
	}
	if policy.Timeout == 0 {
		policy.Timeout = defaultEgressTimeout
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	egress := &Egress{policy: policy, resolver: resolver}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           egress.DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   2,
		MaxConnsPerHost:       4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	egress.client = &http.Client{
		Transport: transport,
		Timeout:   policy.Timeout,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) > policy.MaxRedirects {
				return ErrEgressDenied
			}
			return egress.ValidateURL(request.URL)
		},
	}
	return egress, nil
}

// Client returns the egress HTTP client. It never honors environment proxies and never follows
// more redirects than the policy allows; each followed redirect is re-validated and re-resolved.
func (e *Egress) Client() *http.Client {
	if e == nil {
		return nil
	}
	return e.client
}

// ValidateURL applies the static destination rules: HTTPS only, no userinfo, a public literal
// address or a dotted hostname, and an allowed port. Hostname resolution and address vetting happen
// again on every dial so DNS rebinding cannot redirect a request after validation.
func (e *Egress) ValidateURL(target *url.URL) error {
	if e == nil || target == nil {
		return ErrEgressDenied
	}
	if !strings.EqualFold(target.Scheme, "https") {
		return ErrEgressDenied
	}
	if target.User != nil || target.Host == "" || target.Opaque != "" {
		return ErrEgressDenied
	}
	host := target.Hostname()
	if host == "" || strings.Contains(host, "%") || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return ErrEgressDenied
	}
	if !e.portAllowed(target.Port()) {
		return ErrEgressDenied
	}
	if ip := net.ParseIP(host); ip != nil {
		if !isPublicIP(ip) {
			return ErrEgressDenied
		}
		return nil
	}
	if !hostnamePattern.MatchString(strings.ToLower(host)) {
		return ErrEgressDenied
	}
	return nil
}

// DialContext vets every resolved address before dialing, then dials the vetted numeric address so
// a second DNS answer cannot change the destination. A hostname with any non-public answer is
// rejected entirely rather than retried against a different member of the answer set.
func (e *Egress) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if e == nil {
		return nil, ErrEgressDenied
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || !e.portAllowed(port) {
		return nil, ErrEgressDenied
	}
	target, err := e.vetAddress(ctx, host, port)
	if err != nil {
		return nil, err
	}
	dial := e.dial
	if dial == nil {
		dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		dial = dialer.DialContext
	}
	return dial(ctx, network, target)
}

func (e *Egress) vetAddress(ctx context.Context, host, port string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !isPublicIP(ip) {
			return "", ErrEgressDenied
		}
		return net.JoinHostPort(ip.String(), port), nil
	}
	addresses, err := e.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", ErrEgressUnavailable
	}
	if len(addresses) == 0 {
		return "", ErrEgressUnavailable
	}
	for _, address := range addresses {
		if address.Zone != "" || !isPublicIP(address.IP) {
			return "", ErrEgressDenied
		}
	}
	return net.JoinHostPort(addresses[0].IP.String(), port), nil
}

func (e *Egress) portAllowed(port string) bool {
	if port == "" {
		port = strconv.Itoa(defaultEgressPort)
	}
	for _, allowed := range e.policy.Ports {
		if strconv.Itoa(allowed) == port {
			return true
		}
	}
	return false
}

func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return false
	}
	// IPv4-mapped IPv6 addresses are classified as IPv4 so the mapped range itself never makes
	// every IPv4 address look like a reserved IPv6 destination.
	if ipv4 := ip.To4(); ipv4 != nil {
		return !inNetworks(deniedIPv4, ipv4)
	}
	return !inNetworks(deniedIPv6, ip)
}

func inNetworks(networks []*net.IPNet, ip net.IP) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
