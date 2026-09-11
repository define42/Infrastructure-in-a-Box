//go:build integration

package acmevalidate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/lease"
)

// Only the final socket is redirected for tests. The production transport still
// builds the real hostname, selects a checked lease IP, and requires TCP port 80.
func routeToLoopback(t *testing.T, validator *Validator, handler http.Handler) *atomic.Int32 {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	dials := &atomic.Int32{}
	validator.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		if network != "tcp4" || address != "192.168.50.10:80" {
			return nil, fmt.Errorf("unsafe validation destination: %s %s", network, address)
		}
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp4", server.Listener.Addr().String())
	}
	return dials
}

func TestValidateHTTP01Responses(t *testing.T) {
	t.Parallel()
	token, authorization := challengeValues()
	cases := []struct {
		name   string
		status int
		body   string
		wantOK bool
	}{
		{name: "correct key authorization", status: http.StatusOK, body: authorization, wantOK: true},
		{name: "trailing whitespace", status: http.StatusOK, body: authorization + " \t\r\n", wantOK: true},
		{name: "wrong body", status: http.StatusOK, body: "wrong"},
		{name: "leading whitespace", status: http.StatusOK, body: " " + authorization},
		{name: "unicode suffix", status: http.StatusOK, body: authorization + "\u00a0"},
		{name: "additional token", status: http.StatusOK, body: authorization + "\n" + authorization},
		{name: "not found", status: http.StatusNotFound, body: authorization},
		{name: "redirect", status: http.StatusFound, body: authorization},
		{name: "oversized", status: http.StatusOK, body: authorization + strings.Repeat(" ", maxResponseBytes)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			validator, registry := newTestValidator(t)
			dials := routeToLoopback(t, validator, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.Host != testName || r.URL.Path != "/.well-known/acme-challenge/"+token || r.URL.RawQuery != "" {
					t.Errorf("incorrect challenge request: %s %s host=%q", r.Method, r.URL, r.Host)
				}
				if tc.status == http.StatusFound {
					w.Header().Set("Location", "http://external.invalid/redirect-target")
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			target, err := validator.Validate(t.Context(), "DEVICE.HOME.ARPA.", token, authorization)
			if tc.wantOK {
				if err != nil || target.IP != registry.lease.IP || target.ClientID != registry.lease.ClientID {
					t.Fatalf("Validate = %v, %v", target, err)
				}
			} else if !errors.Is(err, ErrChallengeFailed) {
				t.Fatalf("Validate error = %v, want ErrChallengeFailed", err)
			}
			if dials.Load() != 1 {
				t.Fatalf("made %d connections, want exactly one pinned connection", dials.Load())
			}
		})
	}
}

func TestValidateRejectsLeaseChanges(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		edit func(*lease.Lease)
	}{
		{name: "new address", edit: func(l *lease.Lease) { l.IP = netip.MustParseAddr("192.168.50.11") }},
		{name: "new owner", edit: func(l *lease.Lease) { l.ClientID = "client-2" }},
		{name: "expired", edit: func(l *lease.Lease) { l.ExpiresAt = time.Now().Add(-time.Second) }},
		{name: "renamed", edit: func(l *lease.Lease) { l.Hostname = "other.home.arpa." }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			validator, registry := newTestValidator(t)
			token, authorization := challengeValues()
			routeToLoopback(t, validator, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				registry.update(tc.edit)
				_, _ = io.WriteString(w, authorization)
			}))
			if _, err := validator.Validate(t.Context(), testName, token, authorization); !errors.Is(err, ErrChallengeFailed) || !strings.Contains(err.Error(), "lease changed") {
				t.Fatalf("Validate error = %v, want lease reassignment failure", err)
			}
		})
	}
}

func TestValidateIgnoresProxyEnvironment(t *testing.T) {
	var proxyRequests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyRequests.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(proxy.Close)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("ALL_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	validator, _ := newTestValidator(t)
	token, authorization := challengeValues()
	routeToLoopback(t, validator, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, authorization)
	}))
	if _, err := validator.Validate(t.Context(), testName, token, authorization); err != nil {
		t.Fatal(err)
	}
	if proxyRequests.Load() != 0 {
		t.Fatal("validation connected to an environment-configured proxy")
	}
}

func TestValidateCancelsInFlightRequest(t *testing.T) {
	t.Parallel()
	validator, _ := newTestValidator(t)
	token, authorization := challengeValues()
	started := make(chan struct{})
	routeToLoopback(t, validator, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := validator.Validate(ctx, testName, token, authorization)
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("challenge request did not arrive")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Validate error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("validation did not respect context cancellation")
	}
}
