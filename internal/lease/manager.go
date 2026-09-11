// Package lease manages IPv4 leases and the DNS names attached to them.
package lease

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var (
	// ErrPoolExhausted means that no address is available for an offer.
	ErrPoolExhausted = errors.New("DHCP address pool exhausted")
	// ErrUnavailable means that a requested address cannot be used by this client.
	ErrUnavailable = errors.New("DHCP address unavailable")
)

// Lease is an address assignment. Hostname is a fully qualified DNS name with a
// trailing dot, or empty if the client has no registered name.
type Lease struct {
	ClientID  string     `json:"client_id"`
	IP        netip.Addr `json:"ip"`
	Hostname  string     `json:"hostname,omitempty"`
	ExpiresAt time.Time  `json:"expires_at"`
}

// Config defines the address pool, DNS suffix, and lease lifetimes.
type Config struct {
	PoolStart       netip.Addr
	PoolEnd         netip.Addr
	Domain          string
	LeaseDuration   time.Duration
	OfferDuration   time.Duration
	DeclineDuration time.Duration
	// File enables atomic JSON persistence when nonempty. Offers are temporary
	// reservations and are deliberately not restored after a restart.
	File string
}

// Manager serializes address assignment and DNS registration. Construct it with
// New; its zero value is not usable. All exported methods are safe for concurrent
// use. A single process must own the persistence file.
type Manager struct {
	mu    sync.Mutex
	cfg   Config
	now   func() time.Time
	state state
}

type state struct {
	leases   map[string]Lease
	offers   map[string]Lease
	declined map[netip.Addr]time.Time
}

func newState() state {
	return state{
		leases:   make(map[string]Lease),
		offers:   make(map[string]Lease),
		declined: make(map[netip.Addr]time.Time),
	}
}

func (s state) clone() state {
	return state{
		leases:   maps.Clone(s.leases),
		offers:   maps.Clone(s.offers),
		declined: maps.Clone(s.declined),
	}
}

// New validates the configuration and restores any unexpired persisted state.
// Zero offer and decline durations default to one and ten minutes respectively.
func New(cfg Config) (*Manager, error) {
	return newManager(cfg, time.Now)
}

func newManager(cfg Config, now func() time.Time) (*Manager, error) {
	cfg.PoolStart = cfg.PoolStart.Unmap()
	cfg.PoolEnd = cfg.PoolEnd.Unmap()
	if !cfg.PoolStart.Is4() || !cfg.PoolEnd.Is4() || cfg.PoolStart.Compare(cfg.PoolEnd) > 0 {
		return nil, errors.New("lease pool must be an ordered IPv4 address range")
	}
	cfg.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cfg.Domain), "."))
	if !validDNSName(cfg.Domain) {
		return nil, errors.New("lease domain must be a valid DNS name")
	}
	if cfg.LeaseDuration <= 0 {
		return nil, errors.New("lease duration must be positive")
	}
	if cfg.OfferDuration < 0 || cfg.DeclineDuration < 0 {
		return nil, errors.New("offer and decline durations must not be negative")
	}
	if cfg.OfferDuration == 0 {
		cfg.OfferDuration = time.Minute
	}
	if cfg.DeclineDuration == 0 {
		cfg.DeclineDuration = 10 * time.Minute
	}
	m := &Manager{cfg: cfg, now: now, state: newState()}
	if err := m.restore(); err != nil {
		return nil, err
	}
	return m, nil
}

// Offer reserves an address until OfferDuration elapses. It prefers the client's
// current allocation, then a previous offer, then the requested address. Offers
// do not register DNS names. Hostnames supplied only in DISCOVER are retained
// for a subsequent Commit.
func (m *Manager) Offer(clientID string, requested netip.Addr, hostname string) (Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	m.expire(now)
	if !validClientID(clientID) {
		return Lease{}, ErrUnavailable
	}

	name := NormalizeHostname(hostname, m.cfg.Domain)
	current, hasCurrent := m.state.leases[clientID]
	previous, hasPrevious := m.state.offers[clientID]
	if hostname == "" {
		if hasPrevious {
			name = previous.Hostname
		} else if hasCurrent {
			name = current.Hostname
		}
	}

	var ip netip.Addr
	switch {
	case hasCurrent:
		ip = current.IP
	case hasPrevious:
		ip = previous.IP
	default:
		occupied := m.occupied(clientID)
		requested = requested.Unmap()
		if m.inPool(requested) && !occupied[requested] {
			ip = requested
		} else {
			for candidate := m.cfg.PoolStart; candidate.IsValid() && candidate.Compare(m.cfg.PoolEnd) <= 0; candidate = candidate.Next() {
				if !occupied[candidate] {
					ip = candidate
					break
				}
			}
		}
	}
	if !ip.IsValid() {
		return Lease{}, ErrPoolExhausted
	}

	offer := Lease{ClientID: clientID, IP: ip, Hostname: name, ExpiresAt: now.Add(m.cfg.OfferDuration)}
	m.state.offers[clientID] = offer
	return offer, nil
}

// Commit grants or renews a lease, including a free requested address after a
// client reboot. It never takes another client's lease or offer. Reassigning a
// client atomically releases its previous address. An omitted hostname retains
// the matching offer's name or the client's current name. Invalid, reserved, and
// already occupied DNS names do not prevent address assignment.
func (m *Manager) Commit(clientID string, ip netip.Addr, hostname string) (Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	m.expire(now)
	ip = ip.Unmap()
	if !validClientID(clientID) || !m.inPool(ip) || m.occupied(clientID)[ip] {
		return Lease{}, ErrUnavailable
	}

	name := NormalizeHostname(hostname, m.cfg.Domain)
	if hostname == "" {
		if offered, ok := m.state.offers[clientID]; ok && offered.IP == ip {
			name = offered.Hostname
		} else if current, ok := m.state.leases[clientID]; ok {
			name = current.Hostname
		}
	}
	if name == "ns."+m.cfg.Domain+"." || name == "gateway."+m.cfg.Domain+"." {
		name = ""
	}
	if name != "" {
		for otherID, current := range m.state.leases {
			if otherID != clientID && current.Hostname == name {
				name = ""
				break
			}
		}
	}

	committed := Lease{ClientID: clientID, IP: ip, Hostname: name, ExpiresAt: now.Add(m.cfg.LeaseDuration)}
	next := m.state.clone()
	next.leases[clientID] = committed
	delete(next.offers, clientID)
	if err := m.publish(next); err != nil {
		return Lease{}, err
	}
	return committed, nil
}

// Release removes only the matching client's allocation and its DNS record.
func (m *Manager) Release(clientID string, ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.expire(m.now())
	ip = ip.Unmap()
	if !m.owns(clientID, ip) {
		return ErrUnavailable
	}
	next := m.state.clone()
	next.remove(clientID, ip)
	return m.publish(next)
}

// Decline removes the matching allocation and quarantines the address. A client
// can decline only its own live lease or offer, preventing arbitrary pool loss.
func (m *Manager) Decline(clientID string, ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	m.expire(now)
	ip = ip.Unmap()
	if !m.owns(clientID, ip) {
		return ErrUnavailable
	}
	next := m.state.clone()
	next.remove(clientID, ip)
	next.declined[ip] = now.Add(m.cfg.DeclineDuration)
	return m.publish(next)
}

// LookupName returns a live committed lease for a case-insensitive DNS name.
// A single label is resolved relative to the configured domain.
func (m *Manager) LookupName(name string) (Lease, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.expire(m.now())
	name = NormalizeHostname(name, m.cfg.Domain)
	if name == "" {
		return Lease{}, false
	}
	for _, current := range m.state.leases {
		if current.Hostname == name {
			return current, true
		}
	}
	return Lease{}, false
}

// LookupIP returns a live committed lease, even if it has no registered name.
func (m *Manager) LookupIP(ip netip.Addr) (Lease, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.expire(m.now())
	ip = ip.Unmap()
	for _, current := range m.state.leases {
		if current.IP == ip {
			return current, true
		}
	}
	return Lease{}, false
}

func (m *Manager) inPool(ip netip.Addr) bool {
	return ip.Is4() && ip.Compare(m.cfg.PoolStart) >= 0 && ip.Compare(m.cfg.PoolEnd) <= 0
}

func validClientID(clientID string) bool {
	// JSON replaces invalid UTF-8, which could otherwise change ownership after
	// restart. Callers should encode opaque DHCP identifiers as hexadecimal.
	return clientID != "" && utf8.ValidString(clientID)
}

func (m *Manager) occupied(clientID string) map[netip.Addr]bool {
	occupied := make(map[netip.Addr]bool, len(m.state.leases)+len(m.state.offers)+len(m.state.declined))
	for otherID, current := range m.state.leases {
		if otherID != clientID {
			occupied[current.IP] = true
		}
	}
	for otherID, offer := range m.state.offers {
		if otherID != clientID {
			occupied[offer.IP] = true
		}
	}
	for ip := range m.state.declined {
		occupied[ip] = true
	}
	return occupied
}

func (m *Manager) owns(clientID string, ip netip.Addr) bool {
	if current, ok := m.state.leases[clientID]; ok && current.IP == ip {
		return true
	}
	offer, ok := m.state.offers[clientID]
	return ok && offer.IP == ip
}

func (s state) remove(clientID string, ip netip.Addr) {
	if current, ok := s.leases[clientID]; ok && current.IP == ip {
		delete(s.leases, clientID)
	}
	if offer, ok := s.offers[clientID]; ok && offer.IP == ip {
		delete(s.offers, clientID)
	}
}

func (m *Manager) expire(now time.Time) {
	// Expiry need not rewrite the file: absolute expiration times are also
	// checked during restore, so expired state cannot reappear after restart.
	for clientID, current := range m.state.leases {
		if !current.ExpiresAt.After(now) {
			delete(m.state.leases, clientID)
		}
	}
	for clientID, offer := range m.state.offers {
		if !offer.ExpiresAt.After(now) {
			delete(m.state.offers, clientID)
		}
	}
	for ip, until := range m.state.declined {
		if !until.After(now) {
			delete(m.state.declined, ip)
		}
	}
}

func (m *Manager) publish(next state) error {
	// Keep the lock across persistence so an acknowledgment and DNS visibility
	// always refer to the same successfully saved state.
	if err := m.persist(next); err != nil {
		return fmt.Errorf("persist leases: %w", err)
	}
	m.state = next
	return nil
}
