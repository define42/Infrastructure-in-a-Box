package acmeserver

import (
	"net/http"
	"net/netip"
	"strconv"
	"time"
)

// Use the socket peer, never forwarding headers or the requested identifier.
// Client IDs keep the quota stable across lease renewals and address changes.
func (s *Server) sourceLease(r *http.Request) (string, *problem) {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err == nil && s.cfg.Leases != nil {
		ip := peer.Addr().Unmap()
		current, ok := s.cfg.Leases.LookupIP(ip)
		if ok && current.IP == ip && current.ClientID != "" && s.now().Before(current.ExpiresAt) {
			return current.ClientID, nil
		}
	}
	return "", failure(403, "unauthorized", "account and order creation requires an active source DHCP lease")
}

// The caller holds s.mu for all quota and activity operations. Histories are
// copied when filtered so an unsuccessful commit cannot mutate the old snapshot.
func recentTimes(times []time.Time, cutoff time.Time) []time.Time {
	var recent []time.Time
	for _, stamp := range times {
		if stamp.After(cutoff) {
			recent = append(recent, stamp)
		}
	}
	return recent
}

func (s *Server) allowCreation(w http.ResponseWriter, source string, accountCreation bool) bool {
	if source == "" {
		s.writeProblem(w, failure(403, "unauthorized", "creation requires a source DHCP lease"))
		return false
	}
	limit := s.state.LeaseLimits[source]
	times, maximum, window := limit.Orders, maxLeaseOrders, orderRateWindow
	if accountCreation {
		times, maximum, window = limit.Accounts, maxLeaseAccounts, accountRateWindow
	}
	recent := recentTimes(times, s.now().Add(-window))
	if len(recent) >= maximum {
		retry := recent[0].Add(window).Sub(s.now())
		s.rateLimited(w, retry, "too many creations from this DHCP lease")
		return false
	}
	if _, exists := s.state.LeaseLimits[source]; !exists && len(s.state.LeaseLimits) >= maxRecords {
		// Expired entries do not block a new lease even before the next commit.
		live := 0
		for _, limit := range s.state.LeaseLimits {
			if len(recentTimes(limit.Accounts, s.now().Add(-accountRateWindow))) != 0 ||
				len(recentTimes(limit.Orders, s.now().Add(-orderRateWindow))) != 0 {
				live++
			}
		}
		if live >= maxRecords {
			s.rateLimited(w, orderRateWindow, "source lease quota capacity has been reached")
			return false
		}
	}
	return true
}

func (s *Server) recordCreation(st *state, source string, accountCreation bool) {
	if st.LeaseLimits == nil {
		st.LeaseLimits = make(map[string]leaseLimit)
	}
	limit := st.LeaseLimits[source]
	if accountCreation {
		limit.Accounts = append(recentTimes(limit.Accounts, s.now().Add(-accountRateWindow)), s.now().UTC())
	} else {
		limit.Orders = append(recentTimes(limit.Orders, s.now().Add(-orderRateWindow)), s.now().UTC())
	}
	st.LeaseLimits[source] = limit
}

func (s *Server) rateLimited(w http.ResponseWriter, retry time.Duration, detail string) {
	seconds := max(1, int64((retry+time.Second-1)/time.Second))
	w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	s.writeProblem(w, failure(429, "rateLimited", detail))
}

func (s *Server) touchAccount(id string) {
	if s.activity == nil {
		s.activity = make(map[string]time.Time)
	}
	// Reading an account must not fsync a snapshot. The next mutation persists
	// this activity along with its own changes.
	s.activity[id] = s.now().UTC()
}
