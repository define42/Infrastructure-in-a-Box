package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/define42/Infrastructure-in-a-Box/internal/config"
	"github.com/define42/Infrastructure-in-a-Box/internal/lease"
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
	leases, err := lease.New(lease.Config{
		Domain: cfg.Domain, PoolStart: cfg.PoolStart,
		PoolEnd: cfg.PoolEnd, LeaseDuration: cfg.LeaseDuration, File: cfg.LeaseFile,
	})
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
		server, err := newGateway(cfg, leases, logger)
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
	if current, err := os.ReadFile(configPath); err != nil || !bytes.Equal(current, data) {
		t.Fatalf("startup modified configuration: %v", err)
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
