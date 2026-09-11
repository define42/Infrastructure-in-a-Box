// Package acmevalidate verifies HTTP-01 challenges against active DHCP leases.
package acmevalidate

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/lease"
)

const (
	validationTimeout = 5 * time.Second
	maxResponseBytes  = 4096
)

var (
	// ErrRejectedIdentifier means a name is outside policy or has no usable lease.
	ErrRejectedIdentifier = errors.New("ACME identifier rejected")
	// ErrChallengeFailed means HTTP-01 did not prove control of the leased name.
	ErrChallengeFailed = errors.New("HTTP-01 challenge failed")
)

// Config restricts validation to DHCP names and addresses within one local zone.
type Config struct {
	Domain string
	Subnet netip.Prefix
}

// Registry looks up live, committed DHCP registrations. It must be safe for
// concurrent calls; offers and upstream DNS records must not be returned.
type Registry interface {
	LookupName(string) (lease.Lease, bool)
}

// Target binds an authorization to the DHCP client and address that proved it.
type Target struct {
	IP       netip.Addr `json:"ip"`
	ClientID string     `json:"client_id"`
}

// Validator checks HTTP-01 responses without using system DNS or HTTP proxies.
// Construct it with New; its exported methods are safe for concurrent use.
type Validator struct {
	cfg         Config
	registry    Registry
	broadcast   netip.Addr
	dialContext func(context.Context, string, string) (net.Conn, error)
}

// New constructs a validator. All production validation connections use TCP 80.
func New(cfg Config, registry Registry) (*Validator, error) {
	cfg.Domain = canonicalName(cfg.Domain)
	if !validDNSName(cfg.Domain) {
		return nil, errors.New("ACME validation domain must be a valid DNS name")
	}
	if !cfg.Subnet.IsValid() || !cfg.Subnet.Addr().Is4() || cfg.Subnet.Bits() > 30 || cfg.Subnet != cfg.Subnet.Masked() {
		return nil, errors.New("ACME validation subnet must be a canonical IPv4 network with usable host addresses")
	}
	if registry == nil {
		return nil, errors.New("ACME validation requires a DHCP registry")
	}
	network := cfg.Subnet.Addr().As4()
	var broadcast [4]byte
	binary.BigEndian.PutUint32(broadcast[:], binary.BigEndian.Uint32(network[:])|uint32(math.MaxUint32)>>cfg.Subnet.Bits())
	dialer := &net.Dialer{Timeout: validationTimeout}
	return &Validator{
		cfg:         cfg,
		registry:    registry,
		broadcast:   netip.AddrFrom4(broadcast),
		dialContext: dialer.DialContext,
	}, nil
}

// Lookup applies identifier policy and returns its current committed DHCP owner.
// Names are ASCII DNS names beneath Domain, with optional final dot; IP literals,
// the zone apex, and the gateway and nameserver's reserved names are rejected.
func (v *Validator) Lookup(name string) (Target, error) {
	name = canonicalName(name)
	if !validDNSName(name) || !strings.HasSuffix(name, "."+v.cfg.Domain) {
		return Target{}, fmt.Errorf("%w: name must be a DNS hostname beneath %s", ErrRejectedIdentifier, v.cfg.Domain)
	}
	if _, err := netip.ParseAddr(name); err == nil || name == "gateway."+v.cfg.Domain || name == "ns."+v.cfg.Domain {
		return Target{}, fmt.Errorf("%w: reserved hostname or IP literal", ErrRejectedIdentifier)
	}
	current, ok := v.registry.LookupName(name)
	if !ok || current.ClientID == "" || !current.ExpiresAt.After(time.Now()) || canonicalName(current.Hostname) != name {
		return Target{}, fmt.Errorf("%w: hostname has no active committed DHCP lease", ErrRejectedIdentifier)
	}
	ip := current.IP
	if !ip.Is4() || (!ip.IsGlobalUnicast() && !ip.IsLoopback()) || !v.cfg.Subnet.Contains(ip) || ip == v.cfg.Subnet.Addr() || ip == v.broadcast {
		return Target{}, fmt.Errorf("%w: leased address is not a usable IPv4 host in %s", ErrRejectedIdentifier, v.cfg.Subnet)
	}
	return Target{IP: ip, ClientID: current.ClientID}, nil
}

// Validate fetches the token from the leased host on port 80 and verifies the
// expected key authorization. Redirects are deliberately rejected: clients must
// serve the challenge directly. Trailing ASCII whitespace is ignored, as allowed
// by RFC 8555 section 8.3. A successful result is rechecked for lease reassignment.
func (v *Validator) Validate(ctx context.Context, name, token, keyAuthorization string) (Target, error) {
	if err := ctx.Err(); err != nil {
		return Target{}, fmt.Errorf("%w: %w", ErrChallengeFailed, err)
	}
	if !validKeyAuthorization(token, keyAuthorization) {
		return Target{}, fmt.Errorf("%w: invalid token or key authorization", ErrChallengeFailed)
	}
	name = canonicalName(name)
	target, err := v.Lookup(name)
	if err != nil {
		return Target{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, validationTimeout)
	defer cancel()

	// Pin each request to the checked lease address, not a fresh DNS result. A
	// fresh transport prevents connection reuse across different lease owners.
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != net.JoinHostPort(name, "80") {
				return nil, errors.New("unexpected HTTP-01 destination")
			}
			return v.dialContext(ctx, "tcp4", net.JoinHostPort(target.IP.String(), "80"))
		},
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 16 << 10,
		ResponseHeaderTimeout:  validationTimeout,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   validationTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+name+"/.well-known/acme-challenge/"+token, nil)
	if err != nil {
		return Target{}, fmt.Errorf("%w: construct request: %w", ErrChallengeFailed, err)
	}
	response, err := client.Do(request)
	if err != nil {
		return Target{}, fmt.Errorf("%w: fetch challenge on TCP port 80: %w", ErrChallengeFailed, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return Target{}, fmt.Errorf("%w: HTTP status %d (redirects are not followed)", ErrChallengeFailed, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return Target{}, fmt.Errorf("%w: read response: %w", ErrChallengeFailed, err)
	}
	if len(body) > maxResponseBytes {
		return Target{}, fmt.Errorf("%w: response exceeds %d bytes", ErrChallengeFailed, maxResponseBytes)
	}
	if strings.TrimRight(string(body), " \t\r\n") != keyAuthorization {
		return Target{}, fmt.Errorf("%w: response does not match key authorization", ErrChallengeFailed)
	}
	if err := ctx.Err(); err != nil {
		return Target{}, fmt.Errorf("%w: %w", ErrChallengeFailed, err)
	}
	current, err := v.Lookup(name)
	if err != nil || current != target {
		return Target{}, fmt.Errorf("%w: DHCP lease changed or expired during validation", ErrChallengeFailed)
	}
	return target, nil
}

func validKeyAuthorization(token, authorization string) bool {
	if len(token) < 22 || len(token) > 128 {
		return false
	}
	decodedToken, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decodedToken) < 16 || base64.RawURLEncoding.EncodeToString(decodedToken) != token {
		return false
	}
	prefix := token + "."
	if !strings.HasPrefix(authorization, prefix) {
		return false
	}
	thumbprint := strings.TrimPrefix(authorization, prefix)
	if len(thumbprint) != 43 {
		return false
	}
	decodedThumbprint, err := base64.RawURLEncoding.Strict().DecodeString(thumbprint)
	return err == nil && len(decodedThumbprint) == 32 && base64.RawURLEncoding.EncodeToString(decodedThumbprint) == thumbprint
}

func canonicalName(name string) string {
	// Lowercase only ASCII: Unicode case folding can turn otherwise forbidden
	// characters (such as the Kelvin sign) into valid ASCII hostname letters.
	return strings.Map(func(c rune) rune {
		if c >= 'A' && c <= 'Z' {
			return c + ('a' - 'A')
		}
		return c
	}, strings.TrimSuffix(name, "."))
}

func validDNSName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}
