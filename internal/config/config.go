// Package config parses and validates configuration for the infrastructure service.
package config

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config describes a single IPv4 subnet served by DHCP, DNS, and an HTTPS gateway.
// An invalid Router means no default gateway is advertised; an empty LeaseFile
// disables persistence and an empty Upstream disables external DNS forwarding.
type Config struct {
	Interface     string
	DHCPAddress   string
	DNSAddress    string
	ServerIP      netip.Addr
	Subnet        netip.Prefix
	PoolStart     netip.Addr
	PoolEnd       netip.Addr
	Router        netip.Addr
	Domain        string
	LeaseDuration time.Duration
	LeaseFile     string
	Upstream      string
	DNSTTL        time.Duration
	HTTPSAddress  string
	CADirectory   string
	ACMEStateFile string
}

// Parse validates command-line arguments without opening sockets or inspecting
// network interfaces. Help is written to output and returns flag.ErrHelp.
func Parse(args []string, output io.Writer) (Config, error) {
	var cfg Config
	var serverIP, subnet, poolStart, poolEnd, router string
	flags := flag.NewFlagSet("infra-box", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.StringVar(
		&cfg.Interface,
		"interface",
		"",
		"network interface serving DHCP (required)",
	)
	flags.StringVar(
		&serverIP,
		"server-ip",
		"",
		"static IPv4 address of this server (required)",
	)
	flags.StringVar(
		&subnet,
		"subnet",
		"",
		"IPv4 subnet in canonical CIDR form, e.g. 192.168.50.0/24 (required)",
	)
	flags.StringVar(
		&poolStart,
		"pool-start",
		"",
		"first address in the DHCP pool (required)",
	)
	flags.StringVar(
		&poolEnd,
		"pool-end",
		"",
		"last address in the DHCP pool, inclusive (required)",
	)
	flags.StringVar(
		&router,
		"router",
		"",
		"existing IPv4 default gateway to advertise (optional)",
	)
	flags.StringVar(
		&cfg.Domain,
		"domain",
		"home.arpa",
		"local DNS domain",
	)
	flags.DurationVar(
		&cfg.LeaseDuration,
		"lease-duration",
		12*time.Hour,
		"lease lifetime, in whole seconds (minimum 1m)",
	)
	flags.StringVar(
		&cfg.LeaseFile,
		"lease-file",
		"leases.json",
		"lease state file; empty disables persistence",
	)
	flags.StringVar(
		&cfg.DNSAddress,
		"dns-listen",
		"",
		"DNS UDP and TCP listen address (default <server-ip>:53)",
	)
	flags.StringVar(
		&cfg.DHCPAddress,
		"dhcp-listen",
		":67",
		"DHCP UDP listen address",
	)
	flags.StringVar(
		&cfg.Upstream,
		"upstream",
		"",
		"numeric IPv4:port for external DNS forwarding (optional)",
	)
	flags.DurationVar(
		&cfg.DNSTTL,
		"dns-ttl",
		time.Minute,
		"maximum DNS record TTL, in whole seconds (minimum 1s)",
	)
	flags.StringVar(
		&cfg.HTTPSAddress,
		"https-listen",
		"",
		"gateway HTTPS listen address (default <server-ip>:443)",
	)
	flags.StringVar(
		&cfg.CADirectory,
		"ca-dir",
		"pki",
		"private CA and gateway certificate directory (must persist across restarts)",
	)
	flags.StringVar(
		&cfg.ACMEStateFile,
		"acme-state",
		"",
		"persistent ACME account, order, and revocation state (default <ca-dir>/acme.json)",
	)
	if err := flags.Parse(args); err != nil {
		return Config{}, err
	}
	if flags.NArg() != 0 {
		return Config{}, fmt.Errorf("unexpected positional argument %q", flags.Arg(0))
	}
	if strings.TrimSpace(cfg.Interface) == "" {
		return Config{}, errors.New("-interface is required")
	}
	var err error
	if cfg.ServerIP, err = parseIPv4("server-ip", serverIP); err != nil {
		return Config{}, err
	}
	if cfg.Subnet, err = netip.ParsePrefix(subnet); err != nil {
		return Config{}, fmt.Errorf("-subnet must be an ipv4 CIDR prefix: %q", subnet)
	}
	if !cfg.Subnet.Addr().Is4() || cfg.Subnet.Bits() > 30 {
		return Config{}, errors.New("-subnet must be an ipv4 network with usable host addresses (/0 through /30)")
	}
	if cfg.Subnet != cfg.Subnet.Masked() {
		return Config{}, fmt.Errorf("-subnet must be canonical; use %s", cfg.Subnet.Masked())
	}
	if cfg.PoolStart, err = parseIPv4("pool-start", poolStart); err != nil {
		return Config{}, err
	}
	if cfg.PoolEnd, err = parseIPv4("pool-end", poolEnd); err != nil {
		return Config{}, err
	}
	if router != "" {
		if cfg.Router, err = parseIPv4("router", router); err != nil {
			return Config{}, err
		}
	}
	if err := cfg.validateNetwork(); err != nil {
		return Config{}, err
	}
	cfg.Domain = strings.ToLower(strings.TrimSuffix(cfg.Domain, "."))
	if err := validateDomain(cfg.Domain); err != nil {
		return Config{}, err
	}
	if err := validateDuration("lease-duration", cfg.LeaseDuration, time.Minute); err != nil {
		return Config{}, err
	}
	if err := validateDuration("dns-ttl", cfg.DNSTTL, time.Second); err != nil {
		return Config{}, err
	}
	if cfg.DNSAddress == "" {
		cfg.DNSAddress = net.JoinHostPort(cfg.ServerIP.String(), "53")
	}
	if cfg.HTTPSAddress == "" {
		cfg.HTTPSAddress = net.JoinHostPort(cfg.ServerIP.String(), "443")
	}
	if strings.TrimSpace(cfg.CADirectory) == "" {
		return Config{}, errors.New("-ca-dir must name a persistent directory")
	}
	if cfg.ACMEStateFile == "" {
		cfg.ACMEStateFile = filepath.Join(cfg.CADirectory, "acme.json")
	}
	if err := cfg.validateACMEStatePath(); err != nil {
		return Config{}, err
	}
	if err := cfg.validateListeners(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validateACMEStatePath() error {
	if strings.TrimSpace(c.ACMEStateFile) == "" {
		return errors.New("-acme-state must name a persistent file")
	}
	statePath, err := filepath.Abs(c.ACMEStateFile)
	if err != nil {
		return fmt.Errorf("resolve -acme-state: %w", err)
	}
	protectedPaths := []string{
		c.CADirectory,
		filepath.Join(c.CADirectory, "root-ca-bundle.pem"),
		filepath.Join(c.CADirectory, "gateway-bundle.pem"),
		filepath.Join(c.CADirectory, "root-ca.pem"),
	}
	if c.LeaseFile != "" {
		protectedPaths = append(protectedPaths, c.LeaseFile)
	}
	for _, path := range protectedPaths {
		protected, err := filepath.Abs(path)
		if err != nil {
			return fmt.Errorf("resolve persistent path: %w", err)
		}
		if statePath == protected {
			return errors.New("-acme-state must differ from the lease file, CA directory, and CA certificate/key files")
		}
	}
	return nil
}

func parseIPv4(name, value string) (netip.Addr, error) {
	if value == "" {
		return netip.Addr{}, fmt.Errorf("-%s is required", name)
	}
	addr, err := netip.ParseAddr(value)
	if err != nil || !addr.Is4() {
		return netip.Addr{}, fmt.Errorf("-%s must be a numeric ipv4 address: %q", name, value)
	}
	if !addr.IsGlobalUnicast() {
		return netip.Addr{}, fmt.Errorf("-%s must be a unicast host address: %q", name, value)
	}
	return addr, nil
}

func (c Config) validateNetwork() error {
	network := c.Subnet.Addr().As4()
	hostMask := uint32(math.MaxUint32) >> c.Subnet.Bits()
	var broadcast [4]byte
	binary.BigEndian.PutUint32(broadcast[:], binary.BigEndian.Uint32(network[:])|hostMask)
	broadcastIP := netip.AddrFrom4(broadcast)
	addresses := []struct {
		name string
		addr netip.Addr
	}{
		{name: "server-ip", addr: c.ServerIP},
		{name: "pool-start", addr: c.PoolStart},
		{name: "pool-end", addr: c.PoolEnd},
	}
	if c.Router.IsValid() {
		addresses = append(addresses, struct {
			name string
			addr netip.Addr
		}{name: "router", addr: c.Router})
	}
	for _, item := range addresses {
		if !c.Subnet.Contains(item.addr) {
			return fmt.Errorf("-%s must belong to subnet %s", item.name, c.Subnet)
		}
		if item.addr == c.Subnet.Addr() || item.addr == broadcastIP {
			return fmt.Errorf("-%s cannot be the subnet network or broadcast address", item.name)
		}
	}
	if c.PoolStart.Compare(c.PoolEnd) > 0 {
		return errors.New("-pool-start must be less than or equal to -pool-end")
	}
	if c.inPool(c.ServerIP) {
		return errors.New("the dhcp pool must not include -server-ip")
	}
	if c.Router.IsValid() && c.inPool(c.Router) {
		return errors.New("the dhcp pool must not include -router")
	}
	return nil
}

func (c Config) inPool(addr netip.Addr) bool {
	return addr.Compare(c.PoolStart) >= 0 && addr.Compare(c.PoolEnd) <= 0
}

func validateDomain(domain string) error {
	// Reserve space for the SOA mailbox's "hostmaster." prefix.
	if len(domain) == 0 || len(domain) > 242 {
		return errors.New("-domain must contain 1 to 242 characters")
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 {
			return errors.New("-domain labels must contain 1 to 63 characters")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("-domain labels must not start or end with a hyphen")
		}
		for _, char := range label {
			isLetter := char >= 'a' && char <= 'z'
			isDigit := char >= '0' && char <= '9'
			if !isLetter && !isDigit && char != '-' {
				return errors.New("-domain labels may contain only ascii letters, digits, and hyphens")
			}
		}
	}
	return nil
}

func validateDuration(name string, value, minimum time.Duration) error {
	if value < minimum || value%time.Second != 0 {
		return fmt.Errorf("-%s must be a whole number of seconds, at least %s", name, minimum)
	}
	if value/time.Second > math.MaxUint32 {
		return fmt.Errorf("-%s cannot exceed %d seconds", name, uint64(math.MaxUint32))
	}
	return nil
}

func (c Config) validateListeners() error {
	dhcp, err := parseAddress("dhcp-listen", c.DHCPAddress, true)
	if err != nil {
		return err
	}
	dns, err := parseAddress("dns-listen", c.DNSAddress, true)
	if err != nil {
		return err
	}
	https, err := parseAddress("https-listen", c.HTTPSAddress, true)
	if err != nil {
		return err
	}
	if !dhcp.Addr().IsUnspecified() && dhcp.Addr() != c.ServerIP {
		return errors.New("-dhcp-listen must bind to all ipv4 addresses or -server-ip")
	}
	if !dns.Addr().IsUnspecified() && dns.Addr() != c.ServerIP {
		return errors.New("-dns-listen must bind to all ipv4 addresses or -server-ip")
	}
	if !https.Addr().IsUnspecified() && https.Addr() != c.ServerIP {
		return errors.New("-https-listen must bind to all ipv4 addresses or -server-ip")
	}
	if dhcp.Port() == dns.Port() {
		return errors.New("-dhcp-listen and -dns-listen must use different udp ports")
	}
	if https.Port() == dns.Port() {
		return errors.New("-https-listen and -dns-listen must use different tcp ports")
	}
	if c.Upstream == "" {
		return nil
	}
	upstream, err := parseAddress("upstream", c.Upstream, false)
	if err != nil {
		return err
	}
	if !upstream.Addr().IsGlobalUnicast() && !upstream.Addr().IsLoopback() {
		return errors.New("-upstream must identify a unicast dns server")
	}
	isServerAddress := upstream.Addr() == c.ServerIP || upstream.Addr() == dns.Addr()
	isWildcardLoopback := dns.Addr().IsUnspecified() && upstream.Addr().IsLoopback()
	if upstream.Port() == dns.Port() && (isServerAddress || isWildcardLoopback) {
		return errors.New("-upstream must not point back to the dns listener")
	}
	return nil
}

func parseAddress(name, value string, allowWildcard bool) (netip.AddrPort, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("-%s must be numeric ipv4:port: %q", name, value)
	}
	if host == "" && allowWildcard {
		host = "0.0.0.0"
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.Is4() {
		return netip.AddrPort{}, fmt.Errorf("-%s must use a numeric ipv4 address: %q", name, value)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, fmt.Errorf("-%s port must be between 1 and 65535", name)
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}
