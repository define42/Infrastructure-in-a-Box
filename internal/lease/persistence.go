package lease

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"
)

type persistedState struct {
	Version  int               `json:"version"`
	Leases   []Lease           `json:"leases"`
	Declined []declinedAddress `json:"declined,omitempty"`
}

type declinedAddress struct {
	IP        netip.Addr `json:"ip"`
	ExpiresAt time.Time  `json:"expires_at"`
}

func (m *Manager) restore() error {
	if m.cfg.File == "" {
		return nil
	}
	f, err := os.Open(m.cfg.File)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open lease file: %w", err)
	}
	defer func() { _ = f.Close() }()

	var saved persistedState
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&saved); err != nil {
		return fmt.Errorf("decode lease file: %w", err)
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("lease file contains trailing data")
	}
	if saved.Version != 1 {
		return fmt.Errorf("unsupported lease file version %d", saved.Version)
	}

	now := m.now()
	addresses := make(map[netip.Addr]bool)
	names := make(map[string]bool)
	for _, current := range saved.Leases {
		if !validClientID(current.ClientID) || !m.inPool(current.IP) || current.ExpiresAt.IsZero() {
			return errors.New("lease file contains an invalid client, address, or expiration")
		}
		if current.Hostname != "" && (NormalizeHostname(current.Hostname, m.cfg.Domain) != current.Hostname || current.Hostname == "ns."+m.cfg.Domain+".") {
			return fmt.Errorf("lease file contains invalid or reserved hostname %q", current.Hostname)
		}
		if !current.ExpiresAt.After(now) {
			continue
		}
		if _, exists := m.state.leases[current.ClientID]; exists {
			return fmt.Errorf("lease file has duplicate client %q", current.ClientID)
		}
		if addresses[current.IP] {
			return fmt.Errorf("lease file has duplicate address %s", current.IP)
		}
		if current.Hostname != "" && names[current.Hostname] {
			return fmt.Errorf("lease file has duplicate hostname %q", current.Hostname)
		}
		addresses[current.IP] = true
		if current.Hostname != "" {
			names[current.Hostname] = true
		}
		if current.Hostname == "gateway."+m.cfg.Domain+"." {
			// Older versions allowed this hostname. Preserve the client's lease
			// while reserving gateway DNS for the built-in HTTPS server.
			current.Hostname = ""
		}
		m.state.leases[current.ClientID] = current
	}
	for _, declined := range saved.Declined {
		if !m.inPool(declined.IP) || declined.ExpiresAt.IsZero() {
			return errors.New("lease file contains an invalid declined address or expiration")
		}
		if !declined.ExpiresAt.After(now) {
			continue
		}
		if addresses[declined.IP] {
			return fmt.Errorf("lease file has duplicate or occupied declined address %s", declined.IP)
		}
		addresses[declined.IP] = true
		m.state.declined[declined.IP] = declined.ExpiresAt
	}
	return nil
}

func (m *Manager) persist(next state) error {
	if m.cfg.File == "" {
		return nil
	}
	saved := persistedState{Version: 1, Leases: make([]Lease, 0, len(next.leases))}
	for _, current := range next.leases {
		saved.Leases = append(saved.Leases, current)
	}
	for ip, until := range next.declined {
		saved.Declined = append(saved.Declined, declinedAddress{IP: ip, ExpiresAt: until})
	}
	slices.SortFunc(saved.Leases, func(a, b Lease) int { return a.IP.Compare(b.IP) })
	slices.SortFunc(saved.Declined, func(a, b declinedAddress) int { return a.IP.Compare(b.IP) })

	dir := filepath.Dir(m.cfg.File)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create lease directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(m.cfg.File)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary lease file: %w", err)
	}
	// Cleanup is best effort; the write, sync, and close below are checked.
	defer func() { _ = os.Remove(tmp.Name()) }()
	defer func() { _ = tmp.Close() }()
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(saved); err != nil {
		return fmt.Errorf("encode lease file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync lease file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close lease file: %w", err)
	}
	if err := os.Rename(tmp.Name(), m.cfg.File); err != nil {
		return fmt.Errorf("replace lease file: %w", err)
	}
	return nil
}
