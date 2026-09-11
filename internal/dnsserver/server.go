// Package dnsserver serves static records, infrastructure hostnames, and active DHCP leases.
package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/dnsname"
	"github.com/define42/Infrastructure-in-a-Box/internal/lease"
	"github.com/miekg/dns"
)

const (
	maxUDPPayload  = 1232
	forwardTimeout = 3 * time.Second
)

// Registry provides active leases. Implementations must support concurrent lookups.
type Registry interface {
	LookupName(name string) (lease.Lease, bool)
	LookupIP(ip netip.Addr) (lease.Lease, bool)
	// HasName reports an active hostname or an ancestor of an active hostname.
	HasName(name string) bool
}

// Config configures the local authoritative zone and optional DNS forwarding.
type Config struct {
	Address  string
	Domain   string
	ServerIP netip.Addr
	Subnet   netip.Prefix
	// ARecords maps local hostnames and wildcard names to static IPv4 addresses.
	// Exact static records take precedence over DHCP names and do not create PTRs.
	ARecords map[string]netip.Addr
	// Upstream is a literal IP address and port, such as "1.1.1.1:53".
	Upstream string
	// TTL caps positive record lifetimes. Zero disables caching.
	TTL time.Duration
}

// Server serves a forward zone and reverse records within the configured subnet.
type Server struct {
	config      Config
	registry    Registry
	logger      *slog.Logger
	nsName      string
	gatewayName string
	staticNames map[string]struct{}
	ttl         uint32
	forwards    chan struct{}
}

// New validates config without opening network sockets.
func New(config Config, registry Registry, logger *slog.Logger) (*Server, error) {
	if registry == nil {
		return nil, errors.New("DNS lease registry is required")
	}
	if err := validateAddress(config.Address, true); err != nil {
		return nil, fmt.Errorf("DNS listen address: %w", err)
	}
	config.Domain = strings.ToLower(dns.Fqdn(strings.TrimSpace(config.Domain)))
	if !validDomain(config.Domain) {
		return nil, errors.New("DNS domain must be a valid non-root hostname")
	}
	aRecords, err := normalizeARecords(config.Domain, config.ARecords)
	if err != nil {
		return nil, err
	}
	config.ARecords = aRecords
	if !config.ServerIP.Is4() || !config.Subnet.IsValid() || !config.Subnet.Addr().Is4() || !config.Subnet.Contains(config.ServerIP) {
		return nil, errors.New("DNS server IP must be IPv4 and within the IPv4 subnet")
	}
	config.Subnet = config.Subnet.Masked()
	if config.TTL < 0 || config.TTL/time.Second > math.MaxUint32 {
		return nil, errors.New("DNS TTL must be between zero and 4294967295 seconds")
	}
	if config.Upstream != "" {
		if err := validateAddress(config.Upstream, false); err != nil {
			return nil, fmt.Errorf("DNS upstream: %w", err)
		}
		listenHost, listenPort, _ := net.SplitHostPort(config.Address)
		upstreamHost, upstreamPort, _ := net.SplitHostPort(config.Upstream)
		upstreamIP, _ := netip.ParseAddr(upstreamHost)
		listenIP, _ := netip.ParseAddr(listenHost)
		if listenPort == upstreamPort && (listenIP == upstreamIP ||
			((listenHost == "" || listenIP.IsUnspecified()) && (upstreamIP.IsLoopback() || upstreamIP == config.ServerIP))) {
			return nil, errors.New("DNS upstream must not point to this DNS listener")
		}
	}
	if logger == nil {
		logger = slog.Default()
	}
	server := &Server{
		config: config, registry: registry, logger: logger,
		nsName: "ns." + config.Domain, ttl: uint32(config.TTL / time.Second),
		gatewayName: "gateway." + config.Domain,
		staticNames: map[string]struct{}{
			config.Domain:              {},
			"ns." + config.Domain:      {},
			"gateway." + config.Domain: {},
		},
		forwards: make(chan struct{}, 128),
	}
	for name := range config.ARecords {
		for name != config.Domain {
			server.staticNames[name] = struct{}{}
			next, _ := dns.NextLabel(name, 0)
			name = name[next:]
		}
	}
	return server, nil
}

func normalizeARecords(domain string, records map[string]netip.Addr) (map[string]netip.Addr, error) {
	normalized := make(map[string]netip.Addr, len(records))
	for name, ip := range records {
		canonical := dnsname.NormalizeARecord(name, domain)
		if canonical == "" {
			return nil, fmt.Errorf("DNS A record %q must name a host within %s", name, domain)
		}
		if canonical == "ns."+domain || canonical == "gateway."+domain {
			return nil, fmt.Errorf("DNS A record %q conflicts with a reserved infrastructure hostname", name)
		}
		if _, exists := normalized[canonical]; exists {
			return nil, fmt.Errorf("DNS A record %q duplicates hostname %s", name, canonical)
		}
		if !ip.Is4() || !ip.IsGlobalUnicast() {
			return nil, fmt.Errorf("DNS A record %q must have a unicast IPv4 address", name)
		}
		normalized[canonical] = ip
	}
	return normalized, nil
}

func validateAddress(address string, listen bool) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 || (!listen && n == 0) {
		return errors.New("port must be a valid numeric port")
	}
	if host == "" && listen {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || (!listen && (ip.IsUnspecified() || ip.IsMulticast())) {
		return errors.New("host must be a literal unicast IP address")
	}
	return nil
}

func validDomain(domain string) bool {
	if len(domain) > 243 || domain == "." {
		return false
	}
	for label := range strings.SplitSeq(strings.TrimSuffix(domain, "."), ".") {
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

// Run listens on UDP and TCP until cancellation or a serving failure. A cancelled
// context shuts down both listeners and in-flight forwarding requests.
func (s *Server) Run(ctx context.Context) error {
	if ctx.Err() != nil {
		return nil
	}
	listenConfig := net.ListenConfig{}
	tcp, err := listenConfig.Listen(ctx, "tcp", s.config.Address)
	if err != nil {
		return fmt.Errorf("listen for TCP DNS: %w", err)
	}
	defer func() { _ = tcp.Close() }()
	// Reuse the selected TCP port when Address requests an ephemeral port.
	udp, err := listenConfig.ListenPacket(ctx, "udp", tcp.Addr().String())
	if err != nil {
		return fmt.Errorf("listen for UDP DNS: %w", err)
	}
	defer func() { _ = udp.Close() }()
	return s.serve(ctx, tcp, udp)
}

func (s *Server) serve(ctx context.Context, tcp net.Listener, udp net.PacketConn) error {
	ctx, cancel := context.WithCancel(ctx)
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		s.serveDNS(ctx, w, request)
	})
	servers := []*dns.Server{
		{Listener: tcp, Handler: handler, ReadTimeout: forwardTimeout, WriteTimeout: forwardTimeout},
		{PacketConn: udp, Handler: handler, UDPSize: maxUDPPayload},
	}
	done := make([]chan error, 0, len(servers))
	defer func() {
		cancel()
		// Each server reaches NotifyStartedFunc (or exits) before shutdown is
		// attempted: ShutdownContext before ActivateAndServe would lose a cancel.
		for i, result := range done {
			shutdownCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), forwardTimeout+time.Second)
			if err := servers[i].ShutdownContext(shutdownCtx); err != nil {
				s.logger.Debug("DNS shutdown", "error", err)
			}
			stop()
			<-result
		}
	}()
	for _, server := range servers {
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		result := make(chan error, 1)
		done = append(done, result)
		go func() {
			result <- server.ActivateAndServe()
			close(result)
		}()
		select {
		case <-ready:
		case err := <-result:
			return fmt.Errorf("start DNS listener: %w", err)
		}
	}
	s.logger.Info("DNS server listening", "address", tcp.Addr(), "domain", s.config.Domain)
	select {
	case <-ctx.Done():
		return nil
	case err := <-done[0]:
		return fmt.Errorf("TCP DNS server stopped: %w", err)
	case err := <-done[1]:
		return fmt.Errorf("UDP DNS server stopped: %w", err)
	}
}

// ServeDNS answers a DNS request. Run also propagates its cancellation context
// into forwarding; this entry point uses the independent forwarding timeout.
func (s *Server) ServeDNS(w dns.ResponseWriter, request *dns.Msg) {
	s.serveDNS(context.Background(), w, request)
}

func (s *Server) serveDNS(ctx context.Context, w dns.ResponseWriter, request *dns.Msg) {
	if request.Response {
		return
	}
	response := new(dns.Msg).SetReply(request)
	response.RecursionAvailable = s.config.Upstream != ""
	if opt := request.IsEdns0(); opt != nil {
		response.SetEdns0(maxUDPPayload, false)
		if opt.Version() != 0 {
			response.Rcode = dns.RcodeBadVers
			s.write(w, request, response)
			return
		}
	}
	switch {
	case request.Opcode != dns.OpcodeQuery:
		response.Rcode = dns.RcodeNotImplemented
	case len(request.Question) != 1:
		response.Rcode = dns.RcodeFormatError
	case request.Question[0].Qclass != dns.ClassINET || request.IsTsig() != nil:
		response.Rcode = dns.RcodeRefused
	case request.Question[0].Qtype == dns.TypeAXFR || request.Question[0].Qtype == dns.TypeIXFR:
		response.Rcode = dns.RcodeRefused
	default:
		question := request.Question[0]
		name := dns.CanonicalName(question.Name)
		if _, valid := dns.IsDomainName(name); !valid {
			response.Rcode = dns.RcodeFormatError
		} else if dns.IsSubDomain(s.config.Domain, name) {
			s.answerLocal(response, name, question.Qtype, s.config.Domain, netip.Addr{})
		} else if zone, ip, local := s.reverseAuthority(name); local {
			s.answerLocal(response, name, question.Qtype, zone, ip)
		} else if s.config.Upstream != "" && request.RecursionDesired {
			response = s.forward(ctx, request, response)
		} else {
			response.Rcode = dns.RcodeRefused
		}
	}
	s.write(w, request, response)
}

func (s *Server) answerLocal(response *dns.Msg, name string, kind uint16, zone string, ip netip.Addr) {
	response.Authoritative = true
	exists := name == zone
	if name == zone {
		switch kind {
		case dns.TypeSOA:
			response.Answer = append(response.Answer, s.soa(zone))
		case dns.TypeNS:
			response.Answer = append(response.Answer, &dns.NS{Hdr: header(name, dns.TypeNS, s.ttl), Ns: s.nsName})
			response.Extra = append(response.Extra, s.addressRecord(s.nsName, s.config.ServerIP, s.ttl))
		}
	}
	if zone == s.config.Domain {
		address, ttl, found := s.lookupLocalAddress(name)
		exists = found
		if address.IsValid() && (kind == dns.TypeA || kind == dns.TypeANY) {
			response.Answer = append(response.Answer, s.addressRecord(name, address, ttl))
		}
	} else if ip.IsValid() {
		if ip == s.config.ServerIP {
			exists = true
			if kind == dns.TypePTR || kind == dns.TypeANY {
				response.Answer = append(response.Answer, &dns.PTR{Hdr: header(name, dns.TypePTR, s.ttl), Ptr: s.nsName})
			}
		} else if entry, found := s.registry.LookupIP(ip); found && entry.Hostname != "" && time.Now().Before(entry.ExpiresAt) {
			exists = true
			if kind == dns.TypePTR || kind == dns.TypeANY {
				response.Answer = append(response.Answer, &dns.PTR{Hdr: header(name, dns.TypePTR, s.leaseTTL(entry)), Ptr: entry.Hostname})
			}
		}
	}
	if !exists {
		response.Rcode = dns.RcodeNameError
	}
	if len(response.Answer) == 0 {
		// DHCP can create a name immediately after this answer. Do not retain
		// negative answers in resolver caches across a new allocation.
		soa := s.soa(zone)
		soa.Hdr.Ttl, soa.Minttl = 0, 0
		response.Ns = append(response.Ns, soa)
	}
}

// lookupLocalAddress also reports existing names without an A record, including
// the zone apex and empty non-terminals created by static or DHCP descendants.
func (s *Server) lookupLocalAddress(name string) (netip.Addr, uint32, bool) {
	if name == s.nsName || name == s.gatewayName {
		return s.config.ServerIP, s.ttl, true
	}
	if address, found := s.config.ARecords[name]; found {
		return address, s.ttl, true
	}
	if name == s.config.Domain {
		return netip.Addr{}, 0, true
	}
	if entry, found := s.registry.LookupName(name); found && time.Now().Before(entry.ExpiresAt) {
		return entry.IP, s.leaseTTL(entry), true
	}
	if s.hasName(name) {
		return netip.Addr{}, 0, true
	}
	// RFC 4592 permits synthesis only at the closest existing ancestor. An
	// ancestor without a wildcard blocks every broader wildcard in the zone.
	for name != s.config.Domain {
		next, _ := dns.NextLabel(name, 0)
		name = name[next:]
		if s.hasName(name) {
			address, found := s.config.ARecords["*."+name]
			return address, s.ttl, found
		}
	}
	return netip.Addr{}, 0, false
}

func (s *Server) hasName(name string) bool {
	_, exists := s.staticNames[name]
	return exists || s.registry.HasName(name)
}

func header(name string, kind uint16, ttl uint32) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: kind, Class: dns.ClassINET, Ttl: ttl}
}

func (s *Server) addressRecord(name string, ip netip.Addr, ttl uint32) *dns.A {
	return &dns.A{Hdr: header(name, dns.TypeA, ttl), A: net.IP(ip.AsSlice())}
}

func (s *Server) soa(zone string) *dns.SOA {
	return &dns.SOA{
		Hdr: header(zone, dns.TypeSOA, s.ttl), Ns: s.nsName, Mbox: "hostmaster." + s.config.Domain,
		Serial: 1, Refresh: 60, Retry: 60, Expire: 3600, Minttl: 0,
	}
}

func (s *Server) leaseTTL(entry lease.Lease) uint32 {
	remaining := time.Until(entry.ExpiresAt)
	if remaining <= 0 {
		return 0
	}
	return uint32(min(remaining/time.Second, time.Duration(s.ttl)))
}

// reverseAuthority chooses an octet-aligned zone wholly inside the subnet. A
// /25 therefore owns individual PTR names, never its neighbouring /25's records.
func (s *Server) reverseAuthority(name string) (string, netip.Addr, bool) {
	const suffix = "in-addr.arpa."
	if !strings.HasSuffix(name, "."+suffix) {
		return "", netip.Addr{}, false
	}
	labels := strings.Split(strings.TrimSuffix(name, "."+suffix), ".")
	var octets [4]byte
	var zone string
	for i := 0; i < min(len(labels), 4); i++ {
		label := labels[len(labels)-1-i]
		n, err := strconv.ParseUint(label, 10, 8)
		if err != nil || strconv.FormatUint(n, 10) != label {
			break
		}
		octets[i] = byte(n)
		if zone == "" && (i+1)*8 >= s.config.Subnet.Bits() && s.config.Subnet.Contains(netip.AddrFrom4(octets)) {
			zone = strings.Join(labels[len(labels)-1-i:], ".") + "." + suffix
		}
		if i == 3 && len(labels) == 4 {
			return zone, netip.AddrFrom4(octets), zone != ""
		}
	}
	return zone, netip.Addr{}, zone != ""
}

func (s *Server) forward(ctx context.Context, request, failure *dns.Msg) *dns.Msg {
	select {
	case s.forwards <- struct{}{}:
		defer func() { <-s.forwards }()
	default:
		failure.Rcode = dns.RcodeServerFailure
		return failure
	}
	ctx, cancel := context.WithTimeout(ctx, forwardTimeout)
	defer cancel()
	query := new(dns.Msg).SetQuestion(request.Question[0].Name, request.Question[0].Qtype)
	query.CheckingDisabled = request.CheckingDisabled
	if opt := request.IsEdns0(); opt != nil {
		query.SetEdns0(maxUDPPayload, opt.Do())
	}
	client := dns.Client{Net: "udp", Timeout: forwardTimeout, UDPSize: maxUDPPayload}
	answer, err := s.exchange(ctx, &client, query)
	if err == nil && answer.Truncated {
		client.Net = "tcp"
		answer, err = s.exchange(ctx, &client, query)
	}
	if err != nil {
		s.logger.Debug("DNS forwarding failed", "upstream", s.config.Upstream, "error", err)
		failure.Rcode = dns.RcodeServerFailure
		return failure
	}
	if !answer.Response || answer.Opcode != dns.OpcodeQuery || len(answer.Question) != 1 ||
		!strings.EqualFold(answer.Question[0].Name, query.Question[0].Name) ||
		answer.Question[0].Qtype != query.Question[0].Qtype || answer.Question[0].Qclass != dns.ClassINET {
		failure.Rcode = dns.RcodeServerFailure
		return failure
	}
	answer.Id = request.Id
	answer.Authoritative = false
	answer.AuthenticatedData = false // This server does not validate DNSSEC.
	answer.RecursionAvailable = true
	return answer
}

func (s *Server) exchange(ctx context.Context, client *dns.Client, query *dns.Msg) (*dns.Msg, error) {
	conn, err := client.DialContext(ctx, s.config.Upstream)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	// miekg/dns applies context deadlines to I/O, but an earlier cancellation
	// does not interrupt an existing read unless its connection is closed.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	answer, _, err := client.ExchangeWithConnContext(ctx, query, conn)
	return answer, err
}

func (s *Server) write(w dns.ResponseWriter, request, response *dns.Msg) {
	if _, tcp := w.RemoteAddr().(*net.TCPAddr); !tcp {
		size := dns.MinMsgSize
		if opt := request.IsEdns0(); opt != nil {
			size = min(max(int(opt.UDPSize()), dns.MinMsgSize), maxUDPPayload)
		}
		response.Truncate(size)
	}
	if err := w.WriteMsg(response); err != nil {
		s.logger.Debug("write DNS response", "error", err)
	}
}
