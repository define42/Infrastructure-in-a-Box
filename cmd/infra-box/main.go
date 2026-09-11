package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/define42/Infrastructure-in-a-Box/internal/acmeserver"
	"github.com/define42/Infrastructure-in-a-Box/internal/acmevalidate"
	"github.com/define42/Infrastructure-in-a-Box/internal/config"
	"github.com/define42/Infrastructure-in-a-Box/internal/dhcpserver"
	"github.com/define42/Infrastructure-in-a-Box/internal/dnsserver"
	"github.com/define42/Infrastructure-in-a-Box/internal/gateway"
	"github.com/define42/Infrastructure-in-a-Box/internal/ldapserver"
	"github.com/define42/Infrastructure-in-a-Box/internal/lease"
	"github.com/define42/Infrastructure-in-a-Box/internal/pki"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Parse(os.Args[1:], os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := checkInterface(cfg.Interface, cfg.ServerIP); err != nil {
		return err
	}
	leases, err := newLeaseManager(cfg)
	if err != nil {
		return fmt.Errorf("initialize leases: %w", err)
	}
	dhcp, err := dhcpserver.New(dhcpserver.Config{
		Interface: cfg.Interface, Address: cfg.DHCPAddress, ServerIP: cfg.ServerIP,
		Subnet: cfg.Subnet, Router: cfg.Router, Domain: cfg.Domain, LeaseDuration: cfg.LeaseDuration,
	}, leases, logger)
	if err != nil {
		return err
	}
	dns, err := dnsserver.New(dnsserver.Config{
		Address: cfg.DNSAddress, Domain: cfg.Domain, ServerIP: cfg.ServerIP,
		Subnet: cfg.Subnet, Upstream: cfg.Upstream, TTL: cfg.DNSTTL, ARecords: cfg.ARecords,
	}, leases, logger)
	if err != nil {
		return err
	}
	ca, err := newCA(cfg)
	if err != nil {
		return err
	}
	https, err := newGateway(cfg, ca, leases, logger)
	if err != nil {
		return err
	}
	ldap, err := newLDAP(cfg, ca, logger)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serve(ctx, dhcp.Run, dns.Run, https.Run, ldap.Run)
}

func newLeaseManager(cfg config.Config) (*lease.Manager, error) {
	names := make([]string, 0, len(cfg.ARecords))
	for name := range cfg.ARecords {
		// Only exact local hosts are reserved; external overrides do not affect DHCP.
		if strings.HasSuffix(name, "."+cfg.Domain+".") && !strings.HasPrefix(name, "*.") {
			names = append(names, name)
		}
	}
	return lease.New(lease.Config{
		PoolStart: cfg.PoolStart, PoolEnd: cfg.PoolEnd, Domain: cfg.Domain,
		LeaseDuration: cfg.LeaseDuration, File: cfg.LeaseFile, ReservedNames: names,
	})
}

func newCA(cfg config.Config) (*pki.Manager, error) {
	baseURL, err := acmeBaseURL(cfg.Domain, cfg.HTTPSAddress)
	if err != nil {
		return nil, err
	}
	// The CA must initialize its empty directory before ACME creates state there.
	ca, err := pki.Open(pki.Config{
		Directory: cfg.CADirectory, Domain: cfg.Domain, ServerIP: cfg.ServerIP,
		CRLURL: baseURL + "/crl",
	})
	if err != nil {
		return nil, fmt.Errorf("initialize private CA: %w", err)
	}
	return ca, nil
}

func newGateway(cfg config.Config, ca *pki.Manager, leases *lease.Manager, logger *slog.Logger) (*gateway.Server, error) {
	baseURL, err := acmeBaseURL(cfg.Domain, cfg.HTTPSAddress)
	if err != nil {
		return nil, err
	}
	validator, err := acmevalidate.New(acmevalidate.Config{
		Domain: cfg.Domain, Subnet: cfg.Subnet,
	}, leases)
	if err != nil {
		return nil, fmt.Errorf("initialize ACME validation: %w", err)
	}
	acme, err := acmeserver.New(acmeserver.Config{
		BaseURL: baseURL, Domain: cfg.Domain, StateFile: cfg.ACMEStateFile,
	}, ca, validator, logger)
	if err != nil {
		return nil, fmt.Errorf("initialize ACME server: %w", err)
	}
	https, err := gateway.New(gateway.Config{
		Address: cfg.HTTPSAddress, Domain: cfg.Domain, ACMEHandler: acme,
	}, ca.RootPEM(), ca.GetCertificate, logger)
	if err != nil {
		return nil, fmt.Errorf("initialize HTTPS gateway: %w", err)
	}
	logger.Info("ACME HTTP-01 enabled", "directory", baseURL+"/directory", "state", cfg.ACMEStateFile)
	return https, nil
}

func newLDAP(cfg config.Config, ca *pki.Manager, logger *slog.Logger) (*ldapserver.Server, error) {
	if _, err := ca.GetLDAPCertificate(nil); err != nil {
		return nil, fmt.Errorf("initialize LDAP certificate: %w", err)
	}
	server, err := ldapserver.New(cfg.LDAP, ca.GetLDAPCertificate, logger)
	if err != nil {
		return nil, fmt.Errorf("initialize LDAP server: %w", err)
	}
	return server, nil
}

func acmeBaseURL(domain, address string) (string, error) {
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("ACME HTTPS listener address: %w", err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", errors.New("ACME HTTPS listener requires a port between 1 and 65535")
	}
	host := "gateway." + domain
	if port != 443 {
		host = net.JoinHostPort(host, strconv.FormatUint(port, 10))
	}
	return "https://" + host + "/acme", nil
}

// serve waits for all services and cancels the others on any service exit.
func serve(ctx context.Context, runners ...func(context.Context) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, len(runners))
	for _, run := range runners {
		go func() { results <- run(ctx) }()
	}
	var result error
	for range runners {
		err := <-results
		cancel()
		result = errors.Join(result, err)
	}
	return result
}

func checkInterface(name string, serverIP netip.Addr) error {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("find DHCP interface: %w", err)
	}
	if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("interface %s is down", name)
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("read interface addresses: %w", err)
	}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr().Unmap() == serverIP {
			return nil
		}
	}
	return fmt.Errorf("server IP %s must be statically configured on interface %s", serverIP, name)
}
