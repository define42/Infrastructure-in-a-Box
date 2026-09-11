// Package acmeserver implements a private ACME v2 service using HTTP-01.
package acmeserver

import (
	"context"
	"crypto/x509"
	"maps"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/acmevalidate"
	"github.com/go-jose/go-jose/v4"
)

const (
	maxAccounts    = 4096
	maxRecords     = 10000
	maxIdentifiers = 16
	orderLifetime  = 24 * time.Hour
	problemPrefix  = "urn:ietf:params:acme:error:"
)

// Config supplies a fixed public URL and persistent state location. BaseURL must
// be an HTTPS URL ending in /acme; it never comes from an HTTP Host header.
type Config struct {
	BaseURL   string
	Domain    string
	StateFile string
}

// Authority signs client public keys, without receiving their private keys.
type Authority interface {
	RootPEM() []byte
	SignCSR([]byte, []string) ([]byte, error)
	CreateCRL([]x509.RevocationListEntry, int64) ([]byte, error)
}

// Validator checks names against local leases and validates HTTP-01 responses.
type Validator interface {
	Lookup(string) (acmevalidate.Target, error)
	Validate(context.Context, string, string, string) (acmevalidate.Target, error)
}

type problem struct {
	Type       string   `json:"type"`
	Detail     string   `json:"detail"`
	Status     int      `json:"status"`
	Algorithms []string `json:"algorithms,omitempty"`
}

func (p *problem) Error() string { return p.Detail }

func failure(status int, kind, detail string) *problem {
	p := &problem{Type: problemPrefix + kind, Detail: detail, Status: status}
	if kind == "badSignatureAlgorithm" {
		p.Algorithms = []string{"ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "EdDSA"}
	}
	return p
}

type identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type account struct {
	ID         string          `json:"id"`
	Key        jose.JSONWebKey `json:"key"`
	Thumbprint string          `json:"thumbprint"`
	Status     string          `json:"status"`
	Contact    []string        `json:"contact,omitempty"`
}

type order struct {
	ID            string       `json:"id"`
	AccountID     string       `json:"account_id"`
	Status        string       `json:"status"`
	Expires       time.Time    `json:"expires"`
	Identifiers   []identifier `json:"identifiers"`
	AuthIDs       []string     `json:"authorization_ids"`
	CertificateID string       `json:"certificate_id,omitempty"`
	CSR           []byte       `json:"csr,omitempty"`
	Error         *problem     `json:"error,omitempty"`
}

type authorization struct {
	ID              string              `json:"id"`
	AccountID       string              `json:"account_id"`
	OrderID         string              `json:"order_id"`
	Name            string              `json:"name"`
	Status          string              `json:"status"`
	Expires         time.Time           `json:"expires"`
	Token           string              `json:"token"`
	ChallengeStatus string              `json:"challenge_status"`
	Validated       *time.Time          `json:"validated,omitempty"`
	Target          acmevalidate.Target `json:"target"`
	Error           *problem            `json:"error,omitempty"`
}

type certificate struct {
	ID        string     `json:"id"`
	AccountID string     `json:"account_id"`
	OrderID   string     `json:"order_id"`
	PEM       []byte     `json:"pem"`
	Serial    string     `json:"serial"`
	NotAfter  time.Time  `json:"not_after"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	Reason    int        `json:"reason,omitempty"`
}

type state struct {
	Version         int                      `json:"version"`
	Domain          string                   `json:"domain"`
	RootFingerprint string                   `json:"root_fingerprint"`
	Accounts        map[string]account       `json:"accounts"`
	Orders          map[string]order         `json:"orders"`
	Authorizations  map[string]authorization `json:"authorizations"`
	Certificates    map[string]certificate   `json:"certificates"`
	CRL             []byte                   `json:"crl,omitempty"`
	CRLNumber       int64                    `json:"crl_number"`
	CRLNextUpdate   time.Time                `json:"crl_next_update"`
}

func (s state) clone() state {
	s.Accounts = maps.Clone(s.Accounts)
	s.Orders = maps.Clone(s.Orders)
	s.Authorizations = maps.Clone(s.Authorizations)
	s.Certificates = maps.Clone(s.Certificates)
	return s
}
