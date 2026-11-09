package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
)

// testHash is the Argon2id PHC string of the password "correct horse", with
// parameters far below any production setting so that tests run fast.
const testHash = "$argon2id$v=19$m=64,t=1,p=1$cHVsc2FyLXRlc3Qtc2FsdA$uyPucYpBTL3QggLzn0NmC8SoC4Vzjt3c7gsjLiRHGWc"

// entry is a Client or End-User in a registry file, as JSON members.
type entry = map[string]any

func secretClient() entry {
	return entry{
		"client_id":                  "rp",
		"token_endpoint_auth_method": "client_secret_basic",
		"client_secret_hash":         testHash,
		"redirect_uris":              []string{"https://rp.example/callback"},
	}
}

func endUser() entry {
	return entry{
		"sub":           "7c9e6679-7425-40de-944b-e07fc1f90ae7",
		"username":      "alice",
		"password_hash": testHash,
	}
}

// jwks returns a JWK Set holding key, which is a public or private P-256
// key, for ES256.
func jwks(t *testing.T, key any) map[string]any {
	t.Helper()
	return jwksFor(t, key, "ES256", "sig")
}

// jwksFor returns a JWK Set holding key, with alg and use, each left out
// if "".
func jwksFor(t *testing.T, key any, alg, use string) map[string]any {
	t.Helper()
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key, KeyID: "k1", Algorithm: alg, Use: use}}})
	if err != nil {
		t.Fatal(err)
	}
	var set map[string]any
	if err := json.Unmarshal(b, &set); err != nil {
		t.Fatal(err)
	}
	return set
}

// writeRegistry writes a registry file and returns its path.
func writeRegistry(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "registry.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// registryJSON encodes a registry file of clients and endUsers.
func registryJSON(t *testing.T, clients, endUsers []entry) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"clients": clients, "end_users": endUsers})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// with returns a copy of e with key set to value, or removed if value is nil.
func with(e entry, key string, value any) entry {
	e = maps.Clone(e)
	if value == nil {
		delete(e, key)
	} else {
		e[key] = value
	}
	return e
}

// pulsar refuses to start on a registry file that is missing or invalid,
// with an error that names PULSAR_REGISTRY and the problem.
//
// REQ-OAUTH-1: a redirect URI is absolute, without a fragment.
// REQ-OAUTH-2: every Client registers its redirect URIs.
// REQ-LOGOUT-10: a post-logout redirect URI is checked as a redirect URI
// is, and listed once per Client.
// REQ-CORE-1: a Subject is unique, at most 255 ASCII characters and
// compared as a case-sensitive string, so it is a UUID in its one
// lowercase form.
// REQ-JWTBCP-1, REQ-JWTBCP-2, REQ-JWA-1: a private_key_jwt Client's key
// names the one algorithm it signs with, which is on the allow-list, and
// is a key that algorithm takes: RSA of at least 2048 bits, or P-256.
func TestRunRefusesRegistry(t *testing.T) {
	t.Parallel()

	// Not cryptotest.SetGlobalRandom: the keys' values do not matter, only
	// their types and sizes, and the tests run in parallel, which a
	// process-wide source forbids.
	ecKey, errEC := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384Key, errP384 := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsa1024Key, errRSA := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // G403: a key too small, for the registry to refuse.
	edKey, _, errEd := ed25519.GenerateKey(rand.Reader)
	if err := errors.Join(errEC, errP384, errRSA, errEd); err != nil {
		t.Fatal(err)
	}
	publicJWKS := jwks(t, &ecKey.PublicKey)
	privateJWKS := jwks(t, ecKey)
	jwtClient := with(with(secretClient(), "client_secret_hash", nil), "token_endpoint_auth_method", "private_key_jwt")
	jwtClient["jwks"] = publicJWKS
	withKey := func(key any, alg, use string) string {
		return registryJSON(t, []entry{with(jwtClient, "jwks", jwksFor(t, key, alg, use))}, nil)
	}
	publicClient := with(with(secretClient(), "client_secret_hash", nil), "token_endpoint_auth_method", "none")
	alice := endUser()
	bob := with(with(endUser(), "username", "bob"), "sub", "0b5c3c62-1f3e-4f2b-9f43-8c1d2e3f4a5b")
	withHash := func(hash string) string {
		return registryJSON(t, nil, []entry{with(endUser(), "password_hash", hash)})
	}

	tests := []struct {
		name     string
		registry string // the file's content; empty for no file at all
		problem  string // what the error must name besides PULSAR_REGISTRY
	}{
		{name: "missing file", registry: "", problem: "no such file"},
		{name: "malformed JSON", registry: `{"clients": [`, problem: "unexpected EOF"},
		{name: "trailing data", registry: `{"clients": [], "end_users": []} {}`, problem: "after top-level value"},
		{name: "null", registry: `null`, problem: "JSON object"},
		{name: "array", registry: `[]`, problem: "array"},
		{name: "unknown member", registry: `{"clients": [], "end_users": [], "admins": []}`, problem: "admins"},
		{name: "duplicate member", registry: `{"clients": [], "clients": []}`, problem: "clients"},
		{name: "member in another case", registry: `{"Clients": []}`, problem: "Clients"},
		{name: "misspelled client member", registry: registryJSON(t, []entry{with(with(secretClient(), "redirect_uris", nil), "redirect_uri", "https://rp.example/callback")}, nil), problem: "redirect_uri"},
		{name: "client without client_id", registry: registryJSON(t, []entry{with(secretClient(), "client_id", nil)}, nil), problem: "client_id is required"},
		{name: "duplicate client_id", registry: registryJSON(t, []entry{secretClient(), secretClient()}, nil), problem: "client_id \"rp\" is not unique"},
		{name: "client without auth method", registry: registryJSON(t, []entry{with(secretClient(), "token_endpoint_auth_method", nil)}, nil), problem: "token_endpoint_auth_method is required"},
		{name: "unsupported auth method", registry: registryJSON(t, []entry{with(secretClient(), "token_endpoint_auth_method", "client_secret_jwt")}, nil), problem: "token_endpoint_auth_method"},
		{name: "secret client without hash", registry: registryJSON(t, []entry{with(secretClient(), "client_secret_hash", nil)}, nil), problem: "client_secret_hash"},
		{name: "secret client with JWKS", registry: registryJSON(t, []entry{with(with(secretClient(), "token_endpoint_auth_method", "client_secret_post"), "jwks", publicJWKS)}, nil), problem: "jwks"},
		{name: "secret hash not Argon2id", registry: registryJSON(t, []entry{with(secretClient(), "client_secret_hash", "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")}, nil), problem: "client_secret_hash"},
		{name: "private_key_jwt client without JWKS", registry: registryJSON(t, []entry{with(jwtClient, "jwks", nil)}, nil), problem: "jwks"},
		{name: "private_key_jwt client with empty JWKS", registry: registryJSON(t, []entry{with(jwtClient, "jwks", map[string]any{"keys": []any{}})}, nil), problem: "jwks"},
		{name: "private_key_jwt client with private key", registry: registryJSON(t, []entry{with(jwtClient, "jwks", privateJWKS)}, nil), problem: "jwks"},
		{name: "private_key_jwt client with secret hash", registry: registryJSON(t, []entry{with(jwtClient, "client_secret_hash", testHash)}, nil), problem: "client_secret_hash"},
		{name: "private_key_jwt key without alg", registry: withKey(&ecKey.PublicKey, "", "sig"), problem: "alg is required"},
		{name: "private_key_jwt key for ES384", registry: withKey(&p384Key.PublicKey, "ES384", "sig"), problem: "alg \"ES384\""},
		{name: "private_key_jwt key for none", registry: withKey(&ecKey.PublicKey, "none", "sig"), problem: "alg \"none\""},
		{name: "private_key_jwt key for EdDSA", registry: withKey(edKey, "EdDSA", "sig"), problem: "alg \"EdDSA\""},
		{name: "private_key_jwt key for encryption", registry: withKey(&ecKey.PublicKey, "ES256", "enc"), problem: "use \"enc\""},
		{name: "private_key_jwt EC key for RS256", registry: withKey(&ecKey.PublicKey, "RS256", "sig"), problem: "RSA key"},
		{name: "private_key_jwt P-384 key for ES256", registry: withKey(&p384Key.PublicKey, "ES256", "sig"), problem: "P-256 key"},
		{name: "private_key_jwt 1024-bit RSA key", registry: withKey(&rsa1024Key.PublicKey, "PS256", "sig"), problem: "at least 2048 bits"},
		{name: "public client with secret hash", registry: registryJSON(t, []entry{with(publicClient, "client_secret_hash", testHash)}, nil), problem: "client_secret_hash"},
		{name: "public client with JWKS", registry: registryJSON(t, []entry{with(publicClient, "jwks", publicJWKS)}, nil), problem: "jwks"},
		{name: "client without redirect URIs", registry: registryJSON(t, []entry{with(secretClient(), "redirect_uris", nil)}, nil), problem: "redirect_uris"},
		{name: "client with empty redirect URIs", registry: registryJSON(t, []entry{with(secretClient(), "redirect_uris", []string{})}, nil), problem: "redirect_uris"},
		{name: "relative redirect URI", registry: registryJSON(t, []entry{with(secretClient(), "redirect_uris", []string{"/callback"})}, nil), problem: "redirect_uris"},
		{name: "redirect URI with fragment", registry: registryJSON(t, []entry{with(secretClient(), "redirect_uris", []string{"https://rp.example/callback#top"})}, nil), problem: "redirect_uris"},
		{name: "redirect URI with empty fragment", registry: registryJSON(t, []entry{with(secretClient(), "redirect_uris", []string{"https://rp.example/callback#"})}, nil), problem: "redirect_uris"},
		{name: "redirect URI not a URI", registry: registryJSON(t, []entry{with(secretClient(), "redirect_uris", []string{"https://rp.example:port/"})}, nil), problem: "redirect_uris"},
		{name: "redirect URI with a space", registry: registryJSON(t, []entry{with(secretClient(), "redirect_uris", []string{"https://rp.example/a b"})}, nil), problem: "redirect_uris"},
		{name: "redirect URI with angle brackets", registry: registryJSON(t, []entry{with(secretClient(), "redirect_uris", []string{"https://rp.example/<x>"})}, nil), problem: "redirect_uris"},
		{name: "https redirect URI without host", registry: registryJSON(t, []entry{with(secretClient(), "redirect_uris", []string{"https:///callback"})}, nil), problem: "redirect_uris"},
		{name: "relative post-logout redirect URI", registry: registryJSON(t, []entry{with(secretClient(), "post_logout_redirect_uris", []string{"/signed-out"})}, nil), problem: "post_logout_redirect_uris[0]"},
		{name: "post-logout redirect URI with fragment", registry: registryJSON(t, []entry{with(secretClient(), "post_logout_redirect_uris", []string{"https://rp.example/signed-out#top"})}, nil), problem: "post_logout_redirect_uris[0]"},
		{name: "post-logout redirect URI not a URI", registry: registryJSON(t, []entry{with(secretClient(), "post_logout_redirect_uris", []string{"https://rp.example/a b"})}, nil), problem: "post_logout_redirect_uris[0]"},
		{name: "https post-logout redirect URI without host", registry: registryJSON(t, []entry{with(secretClient(), "post_logout_redirect_uris", []string{"https:///signed-out"})}, nil), problem: "post_logout_redirect_uris[0]"},
		{name: "duplicate post-logout redirect URI", registry: registryJSON(t, []entry{with(secretClient(), "post_logout_redirect_uris", []string{"https://rp.example/signed-out", "https://rp.example/signed-out"})}, nil), problem: "post_logout_redirect_uris[1]"},
		{name: "End-User without Subject", registry: registryJSON(t, nil, []entry{with(alice, "sub", nil)}), problem: "sub"},
		{name: "Subject not a UUID", registry: registryJSON(t, nil, []entry{with(alice, "sub", "alice")}), problem: "sub"},
		{name: "Subject in uppercase", registry: registryJSON(t, nil, []entry{with(alice, "sub", "7C9E6679-7425-40DE-944B-E07FC1F90AE7")}), problem: "sub"},
		{name: "Subject in braces", registry: registryJSON(t, nil, []entry{with(alice, "sub", "{7c9e6679-7425-40de-944b-e07fc1f90ae7}")}), problem: "sub"},
		{name: "Subject without hyphens", registry: registryJSON(t, nil, []entry{with(alice, "sub", "7c9e6679742540de944be07fc1f90ae7")}), problem: "sub"},
		{name: "duplicate Subject", registry: registryJSON(t, nil, []entry{alice, with(bob, "sub", alice["sub"])}), problem: "is not unique"},
		{name: "End-User without username", registry: registryJSON(t, nil, []entry{with(alice, "username", nil)}), problem: "username is required"},
		{name: "duplicate username", registry: registryJSON(t, nil, []entry{alice, with(bob, "username", "alice")}), problem: "username \"alice\" is not unique"},
		{name: "End-User without password hash", registry: registryJSON(t, nil, []entry{with(alice, "password_hash", nil)}), problem: "password_hash"},
		{name: "unknown claim", registry: registryJSON(t, nil, []entry{with(alice, "claims", map[string]any{"favorite_color": "blue"})}), problem: "favorite_color"},
		{name: "claim of the wrong type", registry: registryJSON(t, nil, []entry{with(alice, "claims", map[string]any{"email_verified": "yes"})}), problem: "email_verified"},
		{name: "Subject among claims", registry: registryJSON(t, nil, []entry{with(alice, "claims", map[string]any{"sub": "someone-else"})}), problem: "sub"},
		{name: "bcrypt hash", registry: withHash("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"), problem: "password_hash"},
		{name: "Argon2i hash", registry: withHash("$argon2i$v=19$m=64,t=1,p=1$cHVsc2FyLXRlc3Qtc2FsdA$uyPucYpBTL3QggLzn0NmC8SoC4Vzjt3c7gsjLiRHGWc"), problem: "password_hash"},
		{name: "Argon2id hash of version 16", registry: withHash("$argon2id$v=16$m=64,t=1,p=1$cHVsc2FyLXRlc3Qtc2FsdA$uyPucYpBTL3QggLzn0NmC8SoC4Vzjt3c7gsjLiRHGWc"), problem: "password_hash"},
		{name: "Argon2id hash without version", registry: withHash("$argon2id$m=64,t=1,p=1$cHVsc2FyLXRlc3Qtc2FsdA$uyPucYpBTL3QggLzn0NmC8SoC4Vzjt3c7gsjLiRHGWc"), problem: "password_hash"},
		{name: "Argon2id hash with too little memory", registry: withHash("$argon2id$v=19$m=7,t=1,p=1$cHVsc2FyLXRlc3Qtc2FsdA$uyPucYpBTL3QggLzn0NmC8SoC4Vzjt3c7gsjLiRHGWc"), problem: "password_hash"},
		{name: "Argon2id hash with more memory than RFC 9106 recommends", registry: withHash("$argon2id$v=19$m=2097153,t=1,p=1$cHVsc2FyLXRlc3Qtc2FsdA$uyPucYpBTL3QggLzn0NmC8SoC4Vzjt3c7gsjLiRHGWc"), problem: "password_hash"},
		{name: "Argon2id hash with no iterations", registry: withHash("$argon2id$v=19$m=64,t=0,p=1$cHVsc2FyLXRlc3Qtc2FsdA$uyPucYpBTL3QggLzn0NmC8SoC4Vzjt3c7gsjLiRHGWc"), problem: "password_hash"},
		{name: "Argon2id hash with no parallelism", registry: withHash("$argon2id$v=19$m=64,t=1,p=0$cHVsc2FyLXRlc3Qtc2FsdA$uyPucYpBTL3QggLzn0NmC8SoC4Vzjt3c7gsjLiRHGWc"), problem: "password_hash"},
		{name: "Argon2id hash with parameters out of order", registry: withHash("$argon2id$v=19$t=1,m=64,p=1$cHVsc2FyLXRlc3Qtc2FsdA$uyPucYpBTL3QggLzn0NmC8SoC4Vzjt3c7gsjLiRHGWc"), problem: "password_hash"},
		{name: "Argon2id hash with a leading zero", registry: withHash("$argon2id$v=19$m=064,t=1,p=1$cHVsc2FyLXRlc3Qtc2FsdA$uyPucYpBTL3QggLzn0NmC8SoC4Vzjt3c7gsjLiRHGWc"), problem: "password_hash"},
		{name: "Argon2id hash with an extra parameter", registry: withHash("$argon2id$v=19$m=64,t=1,p=1,keyid=AAAA$cHVsc2FyLXRlc3Qtc2FsdA$uyPucYpBTL3QggLzn0NmC8SoC4Vzjt3c7gsjLiRHGWc"), problem: "password_hash"},
		{name: "Argon2id hash with a short salt", registry: withHash("$argon2id$v=19$m=64,t=1,p=1$cHVsc2E$uyPucYpBTL3QggLzn0NmC8SoC4Vzjt3c7gsjLiRHGWc"), problem: "password_hash"},
		{name: "Argon2id hash with padded base64", registry: withHash("$argon2id$v=19$m=64,t=1,p=1$cHVsc2FyLXRlc3Qtc2FsdA==$uyPucYpBTL3QggLzn0NmC8SoC4Vzjt3c7gsjLiRHGWc"), problem: "password_hash"},
		{name: "Argon2id hash with invalid base64", registry: withHash("$argon2id$v=19$m=64,t=1,p=1$cHVsc2FyLXRlc3Qtc2FsdA$!!!!"), problem: "password_hash"},
		{name: "Argon2id hash without hash", registry: withHash("$argon2id$v=19$m=64,t=1,p=1$cHVsc2FyLXRlc3Qtc2FsdA"), problem: "password_hash"},
		{name: "plain password", registry: withHash("correct horse"), problem: "password_hash"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "missing.json")
			if tt.registry != "" {
				path = writeRegistry(t, tt.registry)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel() // As in TestRunRefusesInvalidConfig.
			env := map[string]string{
				"PULSAR_ADDR":         "127.0.0.1:0",
				"PULSAR_ISSUER":       loopbackIssuer,
				"PULSAR_DATABASE_URL": postgrestest.UnreachableURL(t),
				"PULSAR_SECRET":       testSecret,
				"PULSAR_REGISTRY":     path,
			}
			getenv := func(key string) string { return env[key] }
			err := run(ctx, nil, getenv, strings.NewReader(""), io.Discard, io.Discard)
			if err == nil || !strings.Contains(err.Error(), "PULSAR_REGISTRY") || !strings.Contains(err.Error(), tt.problem) {
				t.Errorf("run() = %v, want an error naming PULSAR_REGISTRY and %q", err, tt.problem)
			}
		})
	}
}

// pulsar refuses to start without PULSAR_REGISTRY.
func TestRunRequiresRegistry(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // As in TestRunRefusesInvalidConfig.
	env := map[string]string{
		"PULSAR_ADDR":         "127.0.0.1:0",
		"PULSAR_ISSUER":       loopbackIssuer,
		"PULSAR_DATABASE_URL": postgrestest.UnreachableURL(t),
		"PULSAR_SECRET":       testSecret,
	}
	getenv := func(key string) string { return env[key] }
	err := run(ctx, nil, getenv, strings.NewReader(""), io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "PULSAR_REGISTRY") {
		t.Errorf("run() = %v, want an error naming PULSAR_REGISTRY", err)
	}
}

// pulsar starts with a registry of each kind of Client and an End-User
// with claims.
//
// REQ-OAUTH-1, REQ-CORE-1, REQ-LOGOUT-10: the forms the refusals above
// allow.
func TestRunAcceptsRegistry(t *testing.T) {
	t.Parallel()

	// Not cryptotest.SetGlobalRandom, as in TestRunRefusesRegistry.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwtClient := with(with(with(secretClient(), "client_secret_hash", nil), "token_endpoint_auth_method", "private_key_jwt"), "client_id", "jwt")
	jwtClient["jwks"] = jwks(t, &ecKey.PublicKey)
	registry := registryJSON(t,
		[]entry{
			secretClient(),
			with(with(secretClient(), "client_id", "post"), "token_endpoint_auth_method", "client_secret_post"),
			jwtClient,
			with(with(with(secretClient(), "client_secret_hash", nil), "token_endpoint_auth_method", "none"), "client_id", "native"),
			with(with(with(secretClient(), "client_id", "app"), "redirect_uris", []string{
				"https://rp.example/callback?tenant=a",
				"com.example.app:/oauth2redirect",
				"http://127.0.0.1:8080/callback",
			}), "post_logout_redirect_uris", []string{
				"https://rp.example/signed-out?tenant=a",
				"com.example.app:/signed-out",
			}),
		},
		[]entry{
			with(endUser(), "claims", map[string]any{
				"name":           "Alice Example",
				"email":          "alice@example.com",
				"email_verified": true,
				"address":        map[string]any{"country": "NZ"},
				"updated_at":     1700000000,
			}),
			with(with(endUser(), "sub", "0b5c3c62-1f3e-4f2b-9f43-8c1d2e3f4a5b"), "username", "Alice"),
		},
	)

	p := start(t, map[string]string{
		"PULSAR_ISSUER":       loopbackIssuer,
		"PULSAR_DATABASE_URL": postgrestest.NewDatabase(t),
		"PULSAR_REGISTRY":     writeRegistry(t, registry),
	})
	p.waitListening()
	p.waitKeysLoaded()
	if err := p.stop(); err != nil {
		t.Errorf("run() = %v, want nil after cancellation", err)
	}
}
