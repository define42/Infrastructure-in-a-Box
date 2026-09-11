// Package config loads and validates JSON configuration for the infrastructure service.
package config

import (
	"encoding/binary"
	"errors"
	"fmt"
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
// Loaded persistence paths are absolute; relative JSON values resolve beside the file.
// DNSAddress is derived from ServerIP using the fixed DNS port 53.
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
	LDAP          LDAPConfig
	// ARecords maps canonical DNS names (including external names and wildcards) to IPv4 addresses.
	ARecords map[string]netip.Addr
}

// config converts JSON string values into validated runtime settings.
func (settings fileSettings) config() (Config, error) {
	cfg := settings.cfg
	if strings.TrimSpace(cfg.Interface) == "" {
		return Config{}, errors.New("interface is required")
	}
	var err error
	if cfg.ServerIP, err = parseIPv4("server_ip", settings.serverIP); err != nil {
		return Config{}, err
	}
	if cfg.Subnet, err = netip.ParsePrefix(settings.subnet); err != nil {
		return Config{}, fmt.Errorf("subnet must be an ipv4 CIDR prefix: %q", settings.subnet)
	}
	if !cfg.Subnet.Addr().Is4() || cfg.Subnet.Bits() > 30 {
		return Config{}, errors.New("subnet must be an ipv4 network with usable host addresses (/0 through /30)")
	}
	if cfg.Subnet != cfg.Subnet.Masked() {
		return Config{}, fmt.Errorf("subnet must be canonical; use %s", cfg.Subnet.Masked())
	}
	if cfg.PoolStart, err = parseIPv4("pool_start", settings.poolStart); err != nil {
		return Config{}, err
	}
	if cfg.PoolEnd, err = parseIPv4("pool_end", settings.poolEnd); err != nil {
		return Config{}, err
	}
	if settings.router != "" {
		if cfg.Router, err = parseIPv4("router", settings.router); err != nil {
			return Config{}, err
		}
	}
	if err := cfg.validateNetwork(); err != nil {
		return Config{}, err
	}
	for _, char := range cfg.Domain {
		if char > 127 {
			return Config{}, errors.New("domain labels may contain only ascii letters, digits, and hyphens")
		}
	}
	cfg.Domain = strings.ToLower(strings.TrimSuffix(cfg.Domain, "."))
	if err := validateDomain(cfg.Domain); err != nil {
		return Config{}, err
	}
	if cfg.ARecords, err = parseARecords(cfg.Domain, settings.aRecords); err != nil {
		return Config{}, err
	}
	if cfg.LeaseDuration, err = time.ParseDuration(settings.leaseDuration); err != nil {
		return Config{}, fmt.Errorf("lease_duration must be a duration string: %w", err)
	}
	if cfg.DNSTTL, err = time.ParseDuration(settings.dnsTTL); err != nil {
		return Config{}, fmt.Errorf("dns_ttl must be a duration string: %w", err)
	}
	if err := validateDuration("lease_duration", cfg.LeaseDuration, time.Minute); err != nil {
		return Config{}, err
	}
	if err := validateDuration("dns_ttl", cfg.DNSTTL, time.Second); err != nil {
		return Config{}, err
	}
	cfg.DNSAddress = net.JoinHostPort(cfg.ServerIP.String(), "53")
	if cfg.HTTPSAddress == "" {
		cfg.HTTPSAddress = net.JoinHostPort(cfg.ServerIP.String(), "443")
	}
	cfg.LDAP.Listen = net.JoinHostPort(cfg.ServerIP.String(), "389")
	cfg.LDAP.TLSListen = net.JoinHostPort(cfg.ServerIP.String(), "636")
	if cfg.LDAP.BaseDN == "" {
		cfg.LDAP.BaseDN = "dc=" + strings.ReplaceAll(cfg.Domain, ".", ",dc=")
	}
	if err := cfg.LDAP.Validate(); err != nil {
		return Config{}, err
	}
	name := "ldap." + cfg.Domain + "."
	if address, exists := cfg.ARecords[name]; exists && address != cfg.ServerIP {
		return Config{}, errors.New("a_records ldap hostname must point to server_ip")
	}
	if cfg.ARecords == nil {
		cfg.ARecords = make(map[string]netip.Addr)
	}
	cfg.ARecords[name] = cfg.ServerIP
	if strings.TrimSpace(cfg.CADirectory) == "" {
		return Config{}, errors.New("ca_dir must name a persistent directory")
	}
	if cfg.ACMEStateFile == "" {
		cfg.ACMEStateFile = filepath.Join(cfg.CADirectory, "acme.json")
	}
	if strings.TrimSpace(cfg.ACMEStateFile) == "" {
		return Config{}, errors.New("acme_state must name a persistent file")
	}
	if err := cfg.validateListeners(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func parseIPv4(name, value string) (netip.Addr, error) {
	if value == "" {
		return netip.Addr{}, fmt.Errorf("%s is required", name)
	}
	addr, err := netip.ParseAddr(value)
	if err != nil || !addr.Is4() {
		return netip.Addr{}, fmt.Errorf("%s must be a numeric ipv4 address: %q", name, value)
	}
	if !addr.IsGlobalUnicast() {
		return netip.Addr{}, fmt.Errorf("%s must be a unicast host address: %q", name, value)
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
		{name: "server_ip", addr: c.ServerIP},
		{name: "pool_start", addr: c.PoolStart},
		{name: "pool_end", addr: c.PoolEnd},
	}
	if c.Router.IsValid() {
		addresses = append(addresses, struct {
			name string
			addr netip.Addr
		}{name: "router", addr: c.Router})
	}
	for _, item := range addresses {
		if !c.Subnet.Contains(item.addr) {
			return fmt.Errorf("%s must belong to subnet %s", item.name, c.Subnet)
		}
		if item.addr == c.Subnet.Addr() || item.addr == broadcastIP {
			return fmt.Errorf("%s cannot be the subnet network or broadcast address", item.name)
		}
	}
	if c.PoolStart.Compare(c.PoolEnd) > 0 {
		return errors.New("pool_start must be less than or equal to pool_end")
	}
	if c.inPool(c.ServerIP) {
		return errors.New("the dhcp pool must not include server_ip")
	}
	if c.Router.IsValid() && c.inPool(c.Router) {
		return errors.New("the dhcp pool must not include router")
	}
	return nil
}

func (c Config) inPool(addr netip.Addr) bool {
	return addr.Compare(c.PoolStart) >= 0 && addr.Compare(c.PoolEnd) <= 0
}

func validateDomain(domain string) error {
	// Reserve space for the SOA mailbox's "hostmaster." prefix.
	if len(domain) == 0 || len(domain) > 242 {
		return errors.New("domain must contain 1 to 242 characters")
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 {
			return errors.New("domain labels must contain 1 to 63 characters")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("domain labels must not start or end with a hyphen")
		}
		for _, char := range label {
			isLetter := char >= 'a' && char <= 'z'
			isDigit := char >= '0' && char <= '9'
			if !isLetter && !isDigit && char != '-' {
				return errors.New("domain labels may contain only ascii letters, digits, and hyphens")
			}
		}
	}
	return nil
}

func validateDuration(name string, value, minimum time.Duration) error {
	if value < minimum || value%time.Second != 0 {
		return fmt.Errorf("%s must be a whole number of seconds, at least %s", name, minimum)
	}
	if value/time.Second > math.MaxUint32 {
		return fmt.Errorf("%s cannot exceed %d seconds", name, uint64(math.MaxUint32))
	}
	return nil
}

func (c Config) validateListeners() error {
	dhcp, err := parseAddress("dhcp_listen", c.DHCPAddress, true)
	if err != nil {
		return err
	}
	https, err := parseAddress("https_listen", c.HTTPSAddress, true)
	if err != nil {
		return err
	}
	if !dhcp.Addr().IsUnspecified() && dhcp.Addr() != c.ServerIP {
		return errors.New("dhcp_listen must bind to all ipv4 addresses or server_ip")
	}
	if !https.Addr().IsUnspecified() && https.Addr() != c.ServerIP {
		return errors.New("https_listen must bind to all ipv4 addresses or server_ip")
	}
	if dhcp.Port() == 53 {
		return errors.New("dhcp_listen conflicts with DNS on UDP port 53")
	}
	if https.Port() == 53 {
		return errors.New("https_listen conflicts with DNS on TCP port 53")
	}
	for _, listener := range []struct{ name, address string }{
		{name: "LDAP listener", address: c.LDAP.Listen},
		{name: "LDAPS listener", address: c.LDAP.TLSListen},
	} {
		address, err := parseAddress(listener.name, listener.address, false)
		if err != nil {
			return err
		}
		if address.Port() == https.Port() {
			return fmt.Errorf("%s and https_listen must use different tcp ports", listener.name)
		}
	}
	if c.Upstream == "" {
		return nil
	}
	upstream, err := parseAddress("upstream", c.Upstream, false)
	if err != nil {
		return err
	}
	if !upstream.Addr().IsGlobalUnicast() && !upstream.Addr().IsLoopback() {
		return errors.New("upstream must identify a unicast dns server")
	}
	if upstream.Port() == 53 && upstream.Addr() == c.ServerIP {
		return errors.New("upstream must not point back to the dns listener")
	}
	return nil
}

func parseAddress(name, value string, allowWildcard bool) (netip.AddrPort, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%s must be numeric ipv4:port: %q", name, value)
	}
	if host == "" && allowWildcard {
		host = "0.0.0.0"
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.Is4() {
		return netip.AddrPort{}, fmt.Errorf("%s must use a numeric ipv4 address: %q", name, value)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, fmt.Errorf("%s port must be between 1 and 65535", name)
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}
