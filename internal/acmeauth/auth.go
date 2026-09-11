// Package acmeauth verifies ACME's signed HTTP requests and single-use nonces.
package acmeauth

import (
	"bytes"
	"container/list"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256" // JWK thumbprints use SHA-256 through crypto.Hash.
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	maxBodyBytes = 64 << 10
	maxNonces    = 8192
	nonceTTL     = 10 * time.Minute
)

// ErrUnknownAccount is returned by LookupKey for an unknown account URL.
var ErrUnknownAccount = errors.New("unknown ACME account")

// Error describes an ACME problem. Type is the suffix of its ACME error URN.
type Error struct {
	Type   string
	Detail string
	Status int
}

func (e *Error) Error() string { return e.Detail }

// LookupKey resolves an account URL to its current public account key.
// Implementations must be safe for concurrent calls.
type LookupKey func(kid string) (jose.JSONWebKey, error)

// Request contains authenticated payload bytes and their signing identity.
// An empty KeyID identifies a request signed with an embedded public JWK.
type Request struct {
	Payload    []byte
	Key        jose.JSONWebKey
	KeyID      string
	Thumbprint string
}

type nonceEntry struct {
	value   string
	expires time.Time
}

// Verifier authenticates requests and tracks a bounded set of expiring nonces.
// Its methods are safe for concurrent use. Construct one with New.
type Verifier struct {
	lookup LookupKey
	mu     sync.Mutex
	nonces map[string]*list.Element
	queue  list.List
	now    func() time.Time
}

// New creates a verifier. A nil lookup permits only embedded-JWK requests.
func New(lookup LookupKey) *Verifier {
	return &Verifier{lookup: lookup, nonces: make(map[string]*list.Element), now: time.Now}
}

// Nonce issues a fresh, base64url-encoded 256-bit nonce valid for ten minutes.
// When capacity is reached, the oldest outstanding nonce is invalidated.
func (v *Verifier) Nonce() (string, error) {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("generate ACME nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(random[:])
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	for first := v.queue.Front(); first != nil; first = v.queue.Front() {
		entry := first.Value.(nonceEntry)
		if len(v.nonces) < maxNonces && now.Before(entry.expires) {
			break
		}
		delete(v.nonces, entry.value)
		v.queue.Remove(first)
	}
	v.nonces[nonce] = v.queue.PushBack(nonceEntry{value: nonce, expires: now.Add(nonceTTL)})
	return nonce, nil
}

func (v *Verifier) consume(nonce string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	element, ok := v.nonces[nonce]
	if !ok {
		return false
	}
	delete(v.nonces, nonce)
	v.queue.Remove(element)
	return v.now().Before(element.Value.(nonceEntry).expires)
}

// Verify authenticates an application/jose+json request against the canonical
// resource URL advertised by the server, never an untrusted Host header.
func (v *Verifier) Verify(r *http.Request, expectedURL string) (*Request, error) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/jose+json" {
		return nil, problem("malformed", "content type must be application/jose+json", http.StatusUnsupportedMediaType)
	}
	if r.Body == nil {
		return nil, malformed("missing JWS request body")
	}
	if r.ContentLength > maxBodyBytes {
		return nil, problem("malformed", "JWS request exceeds 64 KiB", http.StatusRequestEntityTooLarge)
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return nil, malformed("cannot read JWS request body")
	}
	if len(data) > maxBodyBytes {
		return nil, problem("malformed", "JWS request exceeds 64 KiB", http.StatusRequestEntityTooLarge)
	}
	return verify(data, expectedURL, v.lookup, v.consume)
}

// VerifyKeyChange verifies the inner JWS of an account key rollover. Its key
// must be embedded, its URL must match the outer request, and nonce is forbidden.
// The caller must separately authorize the payload's account and oldKey fields
// against the authenticated outer request before changing the account key.
func VerifyKeyChange(data []byte, expectedURL string) (*Request, error) {
	if len(data) > maxBodyBytes {
		return nil, problem("malformed", "JWS request exceeds 64 KiB", http.StatusRequestEntityTooLarge)
	}
	return verify(data, expectedURL, nil, nil)
}

func verify(data []byte, expectedURL string, lookup LookupKey, consume func(string) bool) (*Request, error) {
	envelope, err := object(data)
	if err != nil || len(envelope) != 3 {
		return nil, malformed("expected a flattened JWS with protected, payload, and signature fields")
	}
	var protected []byte
	for _, name := range []string{"protected", "payload", "signature"} {
		encoded, err := stringValue(envelope[name])
		if err != nil || (name != "payload" && encoded == "") {
			return nil, malformed("JWS fields must be base64url strings")
		}
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
			return nil, malformed("JWS fields must use unpadded base64url encoding")
		}
		if name == "protected" {
			protected = decoded
		}
	}
	header, err := object(protected)
	if err != nil {
		return nil, malformed("invalid JWS protected header")
	}
	if consume == nil {
		if _, exists := header["nonce"]; exists {
			return nil, malformed("inner key-change JWS must omit nonce")
		}
	} else {
		nonce, err := stringValue(header["nonce"])
		if err != nil || nonce == "" || !consume(nonce) {
			return nil, problem("badNonce", "nonce is missing, expired, or already used", http.StatusBadRequest)
		}
	}
	url, err := stringValue(header["url"])
	if err != nil || url == "" {
		return nil, malformed("JWS protected header must include url")
	}
	if url != expectedURL {
		return nil, problem("unauthorized", "JWS url does not match the requested resource", http.StatusForbidden)
	}
	for _, name := range []string{"crit", "jku", "x5u", "x5c", "x5t", "x5t#S256"} {
		if _, exists := header[name]; exists {
			return nil, malformed("unsupported JWS protected header")
		}
	}
	if b64, exists := header["b64"]; exists && !bytes.Equal(bytes.TrimSpace(b64), []byte("true")) {
		return nil, malformed("JWS payload must be base64url encoded")
	}
	alg, err := stringValue(header["alg"])
	if err != nil || !supportedAlgorithm(jose.SignatureAlgorithm(alg)) {
		return nil, problem("badSignatureAlgorithm", "unsupported JWS signature algorithm", http.StatusBadRequest)
	}
	jwk, hasJWK := header["jwk"]
	_, hasKID := header["kid"]
	if hasJWK == hasKID || (consume == nil && hasKID) {
		return nil, malformed("JWS must contain exactly one of jwk or kid; inner key-change JWS requires jwk")
	}
	var key jose.JSONWebKey
	var kid string
	if hasJWK {
		if err := parseKey(jwk, &key); err != nil {
			return nil, err
		}
	} else {
		kid, err = stringValue(header["kid"])
		if err != nil || kid == "" {
			return nil, malformed("JWS kid must be a nonempty account URL")
		}
		if lookup == nil {
			return nil, problem("accountDoesNotExist", "account does not exist", http.StatusBadRequest)
		}
		key, err = lookup(kid)
		if errors.Is(err, ErrUnknownAccount) {
			return nil, problem("accountDoesNotExist", "account does not exist", http.StatusBadRequest)
		}
		if err != nil {
			return nil, fmt.Errorf("look up ACME account key: %w", err)
		}
	}
	thumbprint, err := Thumbprint(key)
	if err != nil {
		return nil, malformed("account key must be a supported public key")
	}
	if !keySupportsAlgorithm(key, jose.SignatureAlgorithm(alg)) {
		return nil, problem("badSignatureAlgorithm", "signature algorithm does not match the account key", http.StatusBadRequest)
	}
	signed, err := jose.ParseSignedJSON(string(data), []jose.SignatureAlgorithm{jose.SignatureAlgorithm(alg)})
	if err != nil || len(signed.Signatures) != 1 {
		return nil, malformed("invalid JWS signature envelope")
	}
	payload, err := signed.Verify(key.Key)
	if err != nil {
		return nil, problem("unauthorized", "JWS signature verification failed", http.StatusForbidden)
	}
	return &Request{Payload: payload, Key: key, KeyID: kid, Thumbprint: thumbprint}, nil
}

func parseKey(data []byte, key *jose.JSONWebKey) error {
	fields, err := object(data)
	if err != nil {
		return malformed("invalid embedded JWK")
	}
	for _, name := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k", "x5u", "x5c"} {
		if _, exists := fields[name]; exists {
			return malformed("JWK must contain only a public account key")
		}
	}
	if err := json.Unmarshal(data, key); err != nil {
		return malformed("invalid embedded JWK")
	}
	return nil
}

// Thumbprint returns the RFC 7638 SHA-256 thumbprint of a supported public key.
func Thumbprint(key jose.JSONWebKey) (string, error) {
	if !validPublicKey(key) {
		return "", errors.New("unsupported or invalid public account key")
	}
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("calculate JWK thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

func validPublicKey(jwk jose.JSONWebKey) bool {
	if jwk.Use != "" && jwk.Use != "sig" {
		return false
	}
	switch key := jwk.Key.(type) {
	case *ecdsa.PublicKey:
		return key != nil && key.X != nil && key.Y != nil &&
			(key.Curve == elliptic.P256() || key.Curve == elliptic.P384() || key.Curve == elliptic.P521()) &&
			key.Curve.IsOnCurve(key.X, key.Y)
	case *rsa.PublicKey:
		return key != nil && key.N != nil && key.N.Sign() > 0 && key.N.BitLen() >= 2048 &&
			key.N.BitLen() <= 8192 && key.N.Bit(0) == 1 && key.E >= 3 && key.E <= 1<<31-1 && key.E%2 == 1
	case ed25519.PublicKey:
		return len(key) == ed25519.PublicKeySize
	default:
		return false
	}
}

func supportedAlgorithm(alg jose.SignatureAlgorithm) bool {
	switch alg {
	case jose.ES256, jose.ES384, jose.ES512, jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.EdDSA:
		return true
	default:
		return false
	}
}

func keySupportsAlgorithm(jwk jose.JSONWebKey, alg jose.SignatureAlgorithm) bool {
	if jwk.Algorithm != "" && jwk.Algorithm != string(alg) {
		return false
	}
	switch key := jwk.Key.(type) {
	case *ecdsa.PublicKey:
		return (key.Curve == elliptic.P256() && alg == jose.ES256) ||
			(key.Curve == elliptic.P384() && alg == jose.ES384) ||
			(key.Curve == elliptic.P521() && alg == jose.ES512)
	case *rsa.PublicKey:
		return alg == jose.RS256 || alg == jose.RS384 || alg == jose.RS512 ||
			alg == jose.PS256 || alg == jose.PS384 || alg == jose.PS512
	case ed25519.PublicKey:
		return alg == jose.EdDSA
	default:
		return false
	}
}

// object preserves exact JSON field names and rejects duplicates, including
// differently escaped spellings. Security decisions and go-jose see one value.
func object(data []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return nil, errors.New("expected JSON object")
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("read JSON field: %w", err)
		}
		name, ok := token.(string)
		if !ok {
			return nil, errors.New("invalid JSON field name")
		}
		if _, exists := fields[name]; exists {
			return nil, errors.New("duplicate JSON field")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("read JSON value: %w", err)
		}
		fields[name] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, fmt.Errorf("close JSON object: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected trailing JSON data")
	}
	return fields, nil
}

func stringValue(data json.RawMessage) (string, error) {
	var value string
	if len(data) == 0 || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return "", errors.New("expected JSON string")
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return "", fmt.Errorf("read JSON string: %w", err)
	}
	return value, nil
}

func problem(kind, detail string, status int) *Error {
	return &Error{Type: kind, Detail: detail, Status: status}
}

func malformed(detail string) *Error {
	return problem("malformed", detail, http.StatusBadRequest)
}
