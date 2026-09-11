package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/define42/Infrastructure-in-a-Box/internal/acmevalidate"
	"github.com/define42/Infrastructure-in-a-Box/internal/config"
)

func TestNewGatewayInitializesCAAndACME(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	data := []byte(`{
		"interface": "eth0",
		"server_ip": "192.168.50.2",
		"subnet": "192.168.50.0/24",
		"pool_start": "192.168.50.10",
		"pool_end": "192.168.50.20",
		"lease_duration": "1h",
		"lease_file": "state/leases.json",
		"https_listen": ":8443",
		"ca_dir": "state/pki"
	}`)
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]string{"-config", configPath}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	leases, err := newLeaseManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var originalRoot []byte
	for range 2 {
		cfg, err = config.Parse([]string{"-config", configPath}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		ca, err := newCA(cfg)
		if err != nil {
			t.Fatal(err)
		}
		server, err := newGateway(cfg, ca, leases, logger)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodGet, "https://gateway.home.arpa:8443/acme/directory", nil)
		request.TLS = &tls.ConnectionState{}
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("ACME directory status = %d: %s", response.Code, response.Body.String())
		}
		var directory map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &directory); err != nil {
			t.Fatal(err)
		}
		if directory["newAccount"] != "https://gateway.home.arpa:8443/acme/new-account" {
			t.Errorf("ACME directory = %v", directory)
		}
		response = httptest.NewRecorder()
		server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/ca.pem", nil))
		if response.Code != http.StatusOK {
			t.Errorf("public CA route status = %d", response.Code)
		}
		if originalRoot == nil {
			originalRoot = bytes.Clone(response.Body.Bytes())
		} else if !bytes.Equal(originalRoot, response.Body.Bytes()) {
			t.Error("reloading the JSON configuration replaced the private CA")
		}
	}
	caDir := filepath.Join(dir, "state", "pki")
	for _, name := range []string{"root-ca-bundle.pem", "gateway-bundle.pem", "root-ca.pem", "acme.json"} {
		if _, err := os.Stat(filepath.Join(caDir, name)); err != nil {
			t.Errorf("missing persistent %s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(caDir, "ldap-bundle.pem")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("gateway initialization created unused LDAP certificate state: %v", err)
	}
	if current, err := os.ReadFile(configPath); err != nil || !bytes.Equal(current, data) {
		t.Fatalf("startup modified configuration: %v", err)
	}
}

func TestDNSOverridesAtStartup(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.json")
	data := []byte(`{
		"interface": "eth0",
		"server_ip": "192.168.50.2",
		"subnet": "192.168.50.0/24",
		"pool_start": "192.168.50.100",
		"pool_end": "192.168.50.200",
		"lease_file": "",
		"a_records": {
			"printer": "192.168.50.10", "@": "192.168.50.2",
			"*": "192.168.50.20", "*.apps.home.arpa": "192.168.50.30",
			"google.com": "192.168.50.40", "*.google.com": "192.168.50.50",
			"nothome.arpa": "192.168.50.60", "home.arpa.example.com": "192.168.50.70"
		}
	}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]string{"-config", path}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	leases, err := newLeaseManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	assigned, err := leases.Commit("client-1", cfg.PoolStart, "printer")
	if err != nil || assigned.Hostname != "" || assigned.IP != cfg.PoolStart {
		t.Fatalf("static name claimed through DHCP: %+v, %v", assigned, err)
	}
	validator, err := acmevalidate.New(acmevalidate.Config{Domain: cfg.Domain, Subnet: cfg.Subnet}, leases)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validator.Lookup("printer.home.arpa"); !errors.Is(err, acmevalidate.ErrRejectedIdentifier) {
		t.Fatalf("static DNS name obtained DHCP authorization: %v", err)
	}
	assigned, err = leases.Commit("client-2", cfg.PoolStart.Next(), "laptop")
	if err != nil || assigned.Hostname != "laptop.home.arpa." {
		t.Fatalf("unrelated DHCP hostname failed: %+v, %v", assigned, err)
	}
	if _, err := validator.Lookup("laptop.home.arpa"); err != nil {
		t.Fatalf("unrelated DHCP authorization failed: %v", err)
	}
	assigned, err = leases.Commit("client-3", cfg.PoolStart.Next().Next(), "dashboard.apps.home.arpa")
	if err != nil || assigned.Hostname != "dashboard.apps.home.arpa." {
		t.Fatalf("wildcard blocked a DHCP hostname: %+v, %v", assigned, err)
	}
	if _, err := validator.Lookup("dashboard.apps.home.arpa"); err != nil {
		t.Fatalf("wildcard blocked exact DHCP authorization: %v", err)
	}
	assigned, err = leases.Commit("client-4", cfg.PoolStart.Next().Next().Next(), "google.com")
	if err != nil || assigned.Hostname != "" {
		t.Fatalf("external override allowed a DHCP registration outside the local domain: %+v, %v", assigned, err)
	}
	assigned, err = leases.Commit("client-4", assigned.IP, "google")
	if err != nil || assigned.Hostname != "google.home.arpa." {
		t.Fatalf("external override blocked a local DHCP hostname: %+v, %v", assigned, err)
	}
	for _, name := range []string{
		"*.home.arpa", "*.apps.home.arpa", "missing.apps.home.arpa", "google.com", "*.google.com", "www.google.com",
	} {
		if _, err := validator.Lookup(name); !errors.Is(err, acmevalidate.ErrRejectedIdentifier) {
			t.Errorf("DNS override granted authorization for %q: %v", name, err)
		}
	}
	if cfg.ARecords["printer.home.arpa."] != netip.MustParseAddr("192.168.50.10") {
		t.Fatal("static address changed during DHCP registration")
	}
}

func TestLDAPStartup(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		ldap map[string]any
	}{
		{name: "omitted LDAP"},
		{name: "empty LDAP", ldap: map[string]any{}},
		{name: "configured directory", ldap: map[string]any{"base_dn": "dc=example,dc=org"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			settings := map[string]any{
				"interface": "eth0", "server_ip": "192.168.50.2",
				"subnet": "192.168.50.0/24", "pool_start": "192.168.50.100",
				"pool_end": "192.168.50.200", "ca_dir": "pki", "lease_file": "",
			}
			if tc.ldap != nil {
				settings["ldap"] = tc.ldap
			}
			data, err := json.Marshal(settings)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "config.json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			ca, err := newCA(cfg)
			if err != nil {
				t.Fatal(err)
			}
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			server, err := newLDAP(cfg, ca, logger)
			if err != nil {
				t.Fatal(err)
			}
			if server == nil {
				t.Fatal("LDAP must always be initialized")
			}
			if _, err := os.Stat(filepath.Join(cfg.CADirectory, "ldap-bundle.pem")); err != nil {
				t.Fatal(err)
			}
			cert, err := ca.GetLDAPCertificate(nil)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(ca.RootPEM()) {
				t.Fatal("invalid public CA")
			}
			for _, name := range []string{"ldap.home.arpa", cfg.ServerIP.String()} {
				if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name}); err != nil {
					t.Fatalf("LDAP certificate verification for %s: %v", name, err)
				}
			}
			if cfg.LDAP.Listen != "192.168.50.2:389" || cfg.LDAP.TLSListen != "192.168.50.2:636" {
				t.Fatalf("unexpected LDAP endpoints: %s, %s", cfg.LDAP.Listen, cfg.LDAP.TLSListen)
			}
			if cfg.ARecords["ldap.home.arpa."] != cfg.ServerIP {
				t.Fatal("LDAP hostname does not resolve to server IP")
			}
			leases, err := newLeaseManager(cfg)
			if err != nil {
				t.Fatal(err)
			}
			assigned, err := leases.Commit("client", cfg.PoolStart, "ldap")
			if err != nil || assigned.Hostname != "" {
				t.Fatalf("DHCP client claimed LDAP name: %+v, %v", assigned, err)
			}
		})
	}
}

func TestACMEBaseURL(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		address string
		want    string
	}{
		{name: "default HTTPS", address: "192.168.50.2:443", want: "https://gateway.home.arpa/acme"},
		{name: "wildcard", address: ":443", want: "https://gateway.home.arpa/acme"},
		{name: "nonstandard HTTPS", address: ":8443", want: "https://gateway.home.arpa:8443/acme"},
		{name: "canonical default port", address: ":0443", want: "https://gateway.home.arpa/acme"},
		{name: "missing port", address: "192.168.50.2"},
		{name: "named port", address: ":https"},
		{name: "zero port", address: ":0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := acmeBaseURL("home.arpa", tc.address)
			if got != tc.want || (err != nil) != (tc.want == "") {
				t.Errorf("acmeBaseURL = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestServeStopsSiblingAndWaits(t *testing.T) {
	t.Parallel()
	failure := errors.New("listener unavailable")
	stopped := make(chan struct{}, 2)
	runner := func(ctx context.Context) error {
		<-ctx.Done()
		stopped <- struct{}{}
		return nil
	}
	err := serve(t.Context(),
		func(context.Context) error { return failure },
		runner,
		runner,
	)
	if !errors.Is(err, failure) {
		t.Fatalf("serve error = %v, want listener error", err)
	}
	if len(stopped) != 2 {
		t.Fatal("serve returned before both other services stopped")
	}
}

func TestServeCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	runner := func(ctx context.Context) error {
		<-ctx.Done()
		return nil
	}
	if err := serve(ctx, runner, runner, runner); err != nil {
		t.Fatal(err)
	}
}
