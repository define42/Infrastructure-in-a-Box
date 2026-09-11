package acmeauth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const testURL = "https://gateway.home.arpa/acme/new-account"

func TestVerifierAuthenticatesEmbeddedAndAccountKeys(t *testing.T) {
	t.Parallel()
	key := testKey(t, elliptic.P256())
	public := jose.JSONWebKey{Key: &key.PublicKey}
	kid := "https://gateway.home.arpa/acme/account/123"
	v := New(func(requestKID string) (jose.JSONWebKey, error) {
		if requestKID != kid {
			return jose.JSONWebKey{}, ErrUnknownAccount
		}
		return public, nil
	})
	for _, tc := range []struct {
		name    string
		kid     string
		payload string
	}{
		{name: "embedded JWK", payload: `{"termsOfServiceAgreed":true}`},
		{name: "account POST-as-GET", kid: kid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := signRequest(t, key, v, tc.kid, []byte(tc.payload))
			request, err := v.Verify(httpRequest(data), testURL)
			if err != nil {
				t.Fatal(err)
			}
			wantThumbprint, err := Thumbprint(public)
			if err != nil {
				t.Fatal(err)
			}
			if string(request.Payload) != tc.payload || request.KeyID != tc.kid || request.Thumbprint != wantThumbprint {
				t.Fatalf("unexpected authenticated request: %+v", request)
			}
			_, err = v.Verify(httpRequest(data), testURL)
			assertProblem(t, err, "badNonce", http.StatusBadRequest)
		})
	}
}

func TestVerifierAcceptsSupportedSigningAlgorithms(t *testing.T) {
	t.Parallel()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		alg  jose.SignatureAlgorithm
		key  any
	}{
		{"P256", jose.ES256, testKey(t, elliptic.P256())},
		{"P384", jose.ES384, testKey(t, elliptic.P384())},
		{"P521", jose.ES512, testKey(t, elliptic.P521())},
		{"RS256", jose.RS256, rsaKey},
		{"RS384", jose.RS384, rsaKey},
		{"RS512", jose.RS512, rsaKey},
		{"PS256", jose.PS256, rsaKey},
		{"PS384", jose.PS384, rsaKey},
		{"PS512", jose.PS512, rsaKey},
		{"Ed25519", jose.EdDSA, edKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := New(nil)
			opts := (&jose.SignerOptions{EmbedJWK: true, NonceSource: v}).WithHeader("url", testURL)
			data := signed(t, tc.key, tc.alg, opts, []byte(`{}`))
			if _, err := v.Verify(httpRequest(data), testURL); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVerifierRejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	key := testKey(t, elliptic.P256())
	for _, tc := range []struct {
		name   string
		mutate func(map[string]json.RawMessage)
		kind   string
		status int
	}{
		{"wrong URL", func(h map[string]json.RawMessage) {
			h["url"] = json.RawMessage(`"https://evil.example/acme/new-account"`)
		}, "unauthorized", 403},
		{"missing URL", func(h map[string]json.RawMessage) { delete(h, "url") }, "malformed", 400},
		{"null URL", func(h map[string]json.RawMessage) { h["url"] = json.RawMessage(`null`) }, "malformed", 400},
		{"missing nonce", func(h map[string]json.RawMessage) { delete(h, "nonce") }, "badNonce", 400},
		{"unknown nonce", func(h map[string]json.RawMessage) { h["nonce"] = json.RawMessage(`"unissued"`) }, "badNonce", 400},
		{"null nonce", func(h map[string]json.RawMessage) { h["nonce"] = json.RawMessage(`null`) }, "badNonce", 400},
		{"no signature algorithm", func(h map[string]json.RawMessage) { delete(h, "alg") }, "badSignatureAlgorithm", 400},
		{"unsigned", func(h map[string]json.RawMessage) { h["alg"] = json.RawMessage(`"none"`) }, "badSignatureAlgorithm", 400},
		{"HMAC confusion", func(h map[string]json.RawMessage) { h["alg"] = json.RawMessage(`"HS256"`) }, "badSignatureAlgorithm", 400},
		{"RSA confusion", func(h map[string]json.RawMessage) { h["alg"] = json.RawMessage(`"RS256"`) }, "badSignatureAlgorithm", 400},
		{"EC curve confusion", func(h map[string]json.RawMessage) { h["alg"] = json.RawMessage(`"ES384"`) }, "badSignatureAlgorithm", 400},
		{"both jwk and kid", func(h map[string]json.RawMessage) { h["kid"] = json.RawMessage(`"account"`) }, "malformed", 400},
		{"neither jwk nor kid", func(h map[string]json.RawMessage) { delete(h, "jwk") }, "malformed", 400},
		{"null JWK", func(h map[string]json.RawMessage) { h["jwk"] = json.RawMessage(`null`) }, "malformed", 400},
		{"critical extension", func(h map[string]json.RawMessage) { h["crit"] = json.RawMessage(`[]`) }, "malformed", 400},
		{"unencoded payload", func(h map[string]json.RawMessage) { h["b64"] = json.RawMessage(`false`) }, "malformed", 400},
		{"remote key", func(h map[string]json.RawMessage) { h["jku"] = json.RawMessage(`"https://evil.example/key"`) }, "malformed", 400},
		{"remote certificate", func(h map[string]json.RawMessage) { h["x5u"] = json.RawMessage(`"https://evil.example/cert"`) }, "malformed", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := New(nil)
			data := changeHeader(t, signRequest(t, key, v, "", []byte(`{}`)), tc.mutate)
			_, err := v.Verify(httpRequest(data), testURL)
			assertProblem(t, err, tc.kind, tc.status)
		})
	}
}

func TestVerifierRejectsPrivateKeyAndDuplicateJSON(t *testing.T) {
	t.Parallel()
	key := testKey(t, elliptic.P256())
	for _, tc := range []struct {
		name  string
		alter func(*testing.T, []byte) []byte
	}{
		{"private JWK", func(t *testing.T, data []byte) []byte {
			return changeHeader(t, data, func(h map[string]json.RawMessage) { h["jwk"] = marshal(t, jose.JSONWebKey{Key: key}) })
		}},
		{"duplicate envelope field", func(t *testing.T, data []byte) []byte {
			return []byte(strings.Replace(string(data), `{`, `{"payload":"",`, 1))
		}},
		{"duplicate protected field", func(t *testing.T, data []byte) []byte {
			envelope := decodeObject(t, data)
			var encoded string
			if err := json.Unmarshal(envelope["protected"], &encoded); err != nil {
				t.Fatal(err)
			}
			header, err := base64.RawURLEncoding.DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}
			header = []byte(strings.Replace(string(header), `{`, `{"\u0061lg":"ES256",`, 1))
			envelope["protected"] = marshal(t, base64.RawURLEncoding.EncodeToString(header))
			return marshal(t, envelope)
		}},
		{"duplicate JWK field", func(t *testing.T, data []byte) []byte {
			return changeHeader(t, data, func(h map[string]json.RawMessage) {
				h["jwk"] = json.RawMessage(strings.Replace(string(h["jwk"]), `{`, `{"kty":"RSA",`, 1))
			})
		}},
		{"unprotected header", func(t *testing.T, data []byte) []byte {
			envelope := decodeObject(t, data)
			envelope["header"] = json.RawMessage(`{}`)
			return marshal(t, envelope)
		}},
		{"general serialization", func(t *testing.T, data []byte) []byte {
			envelope := decodeObject(t, data)
			return marshal(t, map[string]any{"payload": envelope["payload"], "signatures": []any{
				map[string]any{"protected": envelope["protected"], "signature": envelope["signature"]},
				map[string]any{"protected": envelope["protected"], "signature": envelope["signature"]},
			}})
		}},
		{"trailing JSON", func(t *testing.T, data []byte) []byte { return append(data, []byte(`{}`)...) }},
		{"null payload", func(t *testing.T, data []byte) []byte {
			envelope := decodeObject(t, data)
			envelope["payload"] = json.RawMessage(`null`)
			return marshal(t, envelope)
		}},
		{"padded base64url", func(t *testing.T, data []byte) []byte {
			envelope := decodeObject(t, data)
			envelope["payload"] = json.RawMessage(`"e30="`)
			return marshal(t, envelope)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := New(nil)
			data := tc.alter(t, signRequest(t, key, v, "", []byte(`{}`)))
			_, err := v.Verify(httpRequest(data), testURL)
			assertProblem(t, err, "malformed", http.StatusBadRequest)
		})
	}
}

func TestVerifierRejectsUnknownAccountAndWrongKey(t *testing.T) {
	t.Parallel()
	key := testKey(t, elliptic.P256())
	otherKey := testKey(t, elliptic.P256())
	for _, tc := range []struct {
		name   string
		lookup LookupKey
		kind   string
		status int
	}{
		{"unknown account", func(string) (jose.JSONWebKey, error) {
			return jose.JSONWebKey{}, fmt.Errorf("lookup: %w", ErrUnknownAccount)
		}, "accountDoesNotExist", 400},
		{"incorrect signing key", func(string) (jose.JSONWebKey, error) {
			return jose.JSONWebKey{Key: &otherKey.PublicKey}, nil
		}, "unauthorized", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := New(tc.lookup)
			data := signRequest(t, key, v, "account", nil)
			_, err := v.Verify(httpRequest(data), testURL)
			assertProblem(t, err, tc.kind, tc.status)
			_, err = v.Verify(httpRequest(data), testURL)
			assertProblem(t, err, "badNonce", 400)
		})
	}
}

func TestVerifierEnforcesMediaTypeAndBodyLimit(t *testing.T) {
	t.Parallel()
	key := testKey(t, elliptic.P256())
	v := New(nil)
	data := signRequest(t, key, v, "", []byte(`{}`))
	request := httpRequest(data)
	request.Header.Set("Content-Type", "application/jose+json; charset=utf-8")
	if _, err := v.Verify(request, testURL); err != nil {
		t.Fatal(err)
	}
	request = httpRequest(data)
	request.Header.Set("Content-Type", "application/json")
	_, err := v.Verify(request, testURL)
	assertProblem(t, err, "malformed", http.StatusUnsupportedMediaType)
	for _, length := range []int64{-1, maxBodyBytes + 1} {
		request = httpRequest(bytes.Repeat([]byte(" "), maxBodyBytes+1))
		request.ContentLength = length
		_, err = v.Verify(request, testURL)
		assertProblem(t, err, "malformed", http.StatusRequestEntityTooLarge)
	}
	request = httpRequest(bytes.Repeat([]byte(" "), maxBodyBytes))
	_, err = v.Verify(request, testURL)
	assertProblem(t, err, "malformed", http.StatusBadRequest)
}

func TestNonceExpiresAndCapacityIsBounded(t *testing.T) {
	t.Parallel()
	key := testKey(t, elliptic.P256())
	v := New(nil)
	now := time.Now()
	v.now = func() time.Time { return now }
	expired := signRequest(t, key, v, "", nil)
	now = now.Add(nonceTTL)
	_, err := v.Verify(httpRequest(expired), testURL)
	assertProblem(t, err, "badNonce", http.StatusBadRequest)
	oldest := signRequest(t, key, v, "", nil)
	for range maxNonces {
		if _, err := v.Nonce(); err != nil {
			t.Fatal(err)
		}
	}
	_, err = v.Verify(httpRequest(oldest), testURL)
	assertProblem(t, err, "badNonce", http.StatusBadRequest)
	fresh := signRequest(t, key, v, "", nil)
	if _, err := v.Verify(httpRequest(fresh), testURL); err != nil {
		t.Fatalf("fresh nonce was not accepted: %v", err)
	}
}

func TestNonceIsConsumedAtomically(t *testing.T) {
	t.Parallel()
	v := New(nil)
	data := signRequest(t, testKey(t, elliptic.P256()), v, "", nil)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			_, err := v.Verify(httpRequest(data), testURL)
			if err == nil {
				accepted.Add(1)
				return
			}
			assertProblem(t, err, "badNonce", http.StatusBadRequest)
		})
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("accepted replayed request %d times; want 1", accepted.Load())
	}
}

func TestVerifyKeyChangeRequiresNewKeyAndNoNonce(t *testing.T) {
	t.Parallel()
	oldKey := testKey(t, elliptic.P256())
	newKey := testKey(t, elliptic.P256())
	payload := marshal(t, map[string]any{"account": "account", "oldKey": jose.JSONWebKey{Key: &oldKey.PublicKey}})
	opts := (&jose.SignerOptions{EmbedJWK: true}).WithHeader("url", testURL)
	inner := signed(t, newKey, jose.ES256, opts, payload)
	v := New(func(string) (jose.JSONWebKey, error) { return jose.JSONWebKey{Key: &oldKey.PublicKey}, nil })
	outer := signRequest(t, oldKey, v, "account", inner)
	verifiedOuter, err := v.Verify(httpRequest(outer), testURL)
	if err != nil {
		t.Fatal(err)
	}
	verifiedInner, err := VerifyKeyChange(verifiedOuter.Payload, testURL)
	if err != nil {
		t.Fatal(err)
	}
	wantThumbprint, err := Thumbprint(jose.JSONWebKey{Key: &newKey.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(verifiedInner.Payload, payload) || verifiedInner.KeyID != "" || verifiedInner.Thumbprint != wantThumbprint {
		t.Fatalf("unexpected inner request: %+v", verifiedInner)
	}
	withNonce := changeHeader(t, inner, func(h map[string]json.RawMessage) { h["nonce"] = json.RawMessage(`""`) })
	_, err = VerifyKeyChange(withNonce, testURL)
	assertProblem(t, err, "malformed", http.StatusBadRequest)
	withKID := changeHeader(t, inner, func(h map[string]json.RawMessage) {
		delete(h, "jwk")
		h["kid"] = json.RawMessage(`"account"`)
	})
	_, err = VerifyKeyChange(withKID, testURL)
	assertProblem(t, err, "malformed", http.StatusBadRequest)
	_, err = VerifyKeyChange(inner, testURL+"/wrong")
	assertProblem(t, err, "unauthorized", http.StatusForbidden)
}

func TestThumbprintRejectsUnsafeKeys(t *testing.T) {
	t.Parallel()
	key := testKey(t, elliptic.P256())
	smallRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	invalidPoint := func(x, y *big.Int) jose.JSONWebKey {
		return jose.JSONWebKey{Key: &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}} //nolint:staticcheck // Malformed points cannot be constructed through the parsing APIs.
	}
	for _, tc := range []struct {
		name string
		key  jose.JSONWebKey
	}{
		{"nil", jose.JSONWebKey{}},
		{"typed nil", jose.JSONWebKey{Key: (*ecdsa.PublicKey)(nil)}},
		{"nil curve", jose.JSONWebKey{Key: &ecdsa.PublicKey{}}},
		{"nil coordinates", jose.JSONWebKey{Key: &ecdsa.PublicKey{Curve: elliptic.P256()}}},
		{"nil X", invalidPoint(nil, big.NewInt(1))},
		{"nil Y", invalidPoint(big.NewInt(1), nil)},
		{"unsupported curve", jose.JSONWebKey{Key: &ecdsa.PublicKey{Curve: elliptic.P224()}}},
		{"private", jose.JSONWebKey{Key: key}},
		{"symmetric", jose.JSONWebKey{Key: []byte("secret")}},
		{"weak RSA", jose.JSONWebKey{Key: &smallRSA.PublicKey}},
		{"wrong use", jose.JSONWebKey{Key: &key.PublicKey, Use: "enc"}},
		{"invalid curve point", invalidPoint(big.NewInt(1), big.NewInt(1))},
		{"negative coordinate", invalidPoint(big.NewInt(-1), big.NewInt(1))},
		{"oversized coordinate", invalidPoint(smallRSA.N, big.NewInt(1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Thumbprint(tc.key); err == nil {
				t.Fatal("unsafe account key accepted")
			}
		})
	}
}

func testKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func signRequest(t *testing.T, key *ecdsa.PrivateKey, v *Verifier, kid string, payload []byte) []byte {
	t.Helper()
	opts := (&jose.SignerOptions{EmbedJWK: kid == "", NonceSource: v}).WithHeader("url", testURL)
	if kid != "" {
		opts.WithHeader("kid", kid)
	}
	return signed(t, key, jose.ES256, opts, payload)
}

func signed(t *testing.T, key any, alg jose.SignatureAlgorithm, opts *jose.SignerOptions, payload []byte) []byte {
	t.Helper()
	if payload == nil {
		payload = []byte{}
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(jws.FullSerialize())
}

func httpRequest(data []byte) *http.Request {
	r := httptest.NewRequest(http.MethodPost, testURL, bytes.NewReader(data))
	r.Header.Set("Content-Type", "application/jose+json")
	return r
}

func assertProblem(t *testing.T, err error, kind string, status int) {
	t.Helper()
	problem, ok := errors.AsType[*Error](err)
	if !ok || problem.Type != kind || problem.Status != status {
		t.Errorf("got error %#v; want ACME %s with status %d", err, kind, status)
	}
}

func decodeObject(t *testing.T, data []byte) map[string]json.RawMessage {
	t.Helper()
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func marshal(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func changeHeader(t *testing.T, data []byte, change func(map[string]json.RawMessage)) []byte {
	t.Helper()
	envelope := decodeObject(t, data)
	var encoded string
	if err := json.Unmarshal(envelope["protected"], &encoded); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	header := decodeObject(t, decoded)
	change(header)
	envelope["protected"] = marshal(t, base64.RawURLEncoding.EncodeToString(marshal(t, header)))
	return marshal(t, envelope)
}
