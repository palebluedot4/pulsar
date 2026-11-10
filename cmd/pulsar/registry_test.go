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

// ordersServer returns a Resource Server in a registry file, with one
// scope.
func ordersServer() entry {
	return entry{
		"identifier": "https://api.example/orders",
		"scopes":     []entry{{"scope": "orders:read", "description": "read your orders"}},
	}
}

// machineClient returns a Client in a registry file registered for
// client_credentials alone, for ordersServer's scope.
func machineClient() entry {
	return entry{
		"client_id":                  "batch",
		"grant_types":                []string{"client_credentials"},
		"token_endpoint_auth_method": "client_secret_basic",
		"client_secret_hash":         testHash,
		"resource_servers":           []string{"https://api.example/orders"},
		"scope":                      "orders:read",
	}
}

// registryWithResourceServers encodes a registry file of resourceServers
// and clients, and no End-User.
func registryWithResourceServers(t *testing.T, resourceServers, clients []entry) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"resource_servers": resourceServers, "clients": clients, "end_users": []entry{}})
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
// REQ-OAUTH-2: every Client registers its redirect URIs, each once.
// REQ-LOGOUT-10: a post-logout redirect URI is checked as a redirect URI
// is, and listed once per Client too.
// REQ-CORE-1: a Subject is unique, at most 255 ASCII characters and
// compared as a case-sensitive string, so it is a UUID in its one
// lowercase form.
// REQ-JWTBCP-1, REQ-JWTBCP-2, REQ-JWA-1: a private_key_jwt Client's key
// names the one algorithm it signs with, which is on the allow-list, and
// is a key that algorithm takes: RSA of at least 2048 bits, or P-256.
// REQ-RESOURCE-1: a Resource Server's identifier is an absolute URI
// without a fragment, registered once, and its scopes are its own: none
// is one of OpenID Connect's or another Resource Server's. A Client lists
// only Resource Servers registered, each once.
// REQ-AT-5, REQ-BCP-15: no Resource Server's identifier is the issuer,
// the default resource, whose access tokens UserInfo accepts.
// REQ-CLIENTMETA-1, REQ-CLIENTMETA-2, REQ-CLIENTMETA-3, REQ-OAUTH-47:
// grant_types lists client_credentials alone, or authorization_code and
// refresh_token, each once; a machine Client, which lists
// client_credentials, is confidential, registers no redirect or
// post-logout redirect URIs, and lists in scope, by single spaces, scopes
// of the Resource Servers it may request, at least one and each once; no
// other Client lists scope.
// REQ-BCP-17: no Client's client_id is a UUID, in any case, the form of
// every End-User's Subject: a machine Client's is the sub of its access
// tokens, and a code-flow Client's appears beside an End-User's sub in
// theirs.
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
	withIdentifier := func(identifier any) string {
		return registryWithResourceServers(t, []entry{with(ordersServer(), "identifier", identifier)}, nil)
	}
	withScope := func(scope entry) string {
		return registryWithResourceServers(t, []entry{with(ordersServer(), "scopes", []entry{scope})}, nil)
	}
	billingServer := with(with(ordersServer(), "identifier", "https://api.example/billing"), "scopes", []entry{{"scope": "billing:read", "description": "read your invoices"}})
	permitting := func(identifiers ...string) string {
		return registryWithResourceServers(t, []entry{ordersServer()}, []entry{with(secretClient(), "resource_servers", identifiers)})
	}
	withMachine := func(key string, value any) string {
		return registryWithResourceServers(t, []entry{ordersServer(), billingServer}, []entry{with(machineClient(), key, value)})
	}
	withGrantTypes := func(grantTypes ...string) string {
		return registryJSON(t, []entry{with(secretClient(), "grant_types", grantTypes)}, nil)
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
		{name: "duplicate redirect URI", registry: registryJSON(t, []entry{with(secretClient(), "redirect_uris", []string{"https://rp.example/callback", "https://rp.example/callback"})}, nil), problem: "redirect_uris[1]"},
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
		{name: "Resource Server without identifier", registry: withIdentifier(nil), problem: "identifier is required"},
		{name: "relative identifier", registry: withIdentifier("/orders"), problem: "resource_servers[0]"},
		{name: "identifier with fragment", registry: withIdentifier("https://api.example/orders#top"), problem: "fragment"},
		{name: "identifier with empty fragment", registry: withIdentifier("https://api.example/orders#"), problem: "fragment"},
		{name: "identifier not a URI", registry: withIdentifier("https://api.example/a b"), problem: "resource_servers[0]"},
		{name: "https identifier without host", registry: withIdentifier("https:///orders"), problem: "no host"},
		{name: "duplicate identifier", registry: registryWithResourceServers(t, []entry{ordersServer(), with(billingServer, "identifier", "https://api.example/orders")}, nil), problem: "identifier \"https://api.example/orders\" is not unique"},
		{name: "misspelled Resource Server member", registry: registryWithResourceServers(t, []entry{with(ordersServer(), "scope", []string{"orders:read"})}, nil), problem: "scope"},
		{name: "identifier that is the issuer", registry: withIdentifier(loopbackIssuer), problem: "PULSAR_ISSUER"},
		{name: "Resource Server without scopes", registry: registryWithResourceServers(t, []entry{with(ordersServer(), "scopes", nil)}, nil), problem: "at least one scope"},
		{name: "Resource Server with empty scopes", registry: registryWithResourceServers(t, []entry{with(ordersServer(), "scopes", []entry{})}, nil), problem: "at least one scope"},
		{name: "scope without value", registry: withScope(entry{"description": "read your orders"}), problem: "scope is required"},
		{name: "scope without description", registry: withScope(entry{"scope": "orders:read"}), problem: "description is required"},
		{name: "scope with a space", registry: withScope(entry{"scope": "orders read", "description": "read your orders"}), problem: "RFC 6749"},
		{name: "scope with a quotation mark", registry: withScope(entry{"scope": `orders"read`, "description": "read your orders"}), problem: "RFC 6749"},
		{name: "scope with a backslash", registry: withScope(entry{"scope": `orders\read`, "description": "read your orders"}), problem: "RFC 6749"},
		{name: "scope openid", registry: withScope(entry{"scope": "openid", "description": "x"}), problem: "OpenID Connect"},
		{name: "scope profile", registry: withScope(entry{"scope": "profile", "description": "x"}), problem: "OpenID Connect"},
		{name: "scope email", registry: withScope(entry{"scope": "email", "description": "x"}), problem: "OpenID Connect"},
		{name: "scope address", registry: withScope(entry{"scope": "address", "description": "x"}), problem: "OpenID Connect"},
		{name: "scope phone", registry: withScope(entry{"scope": "phone", "description": "x"}), problem: "OpenID Connect"},
		{name: "scope offline_access", registry: withScope(entry{"scope": "offline_access", "description": "x"}), problem: "OpenID Connect"},
		{name: "scope listed twice", registry: registryWithResourceServers(t, []entry{with(ordersServer(), "scopes", []entry{{"scope": "orders:read", "description": "a"}, {"scope": "orders:read", "description": "b"}})}, nil), problem: "scopes[1]"},
		{name: "scope of another Resource Server", registry: registryWithResourceServers(t, []entry{ordersServer(), with(billingServer, "scopes", []entry{{"scope": "orders:read", "description": "x"}})}, nil), problem: "https://api.example/orders"},
		{name: "client naming an unknown Resource Server", registry: permitting("https://api.example/billing"), problem: "resource_servers[0]"},
		{name: "client naming a Resource Server twice", registry: permitting("https://api.example/orders", "https://api.example/orders"), problem: "resource_servers[1]"},
		{name: "unknown grant type", registry: withGrantTypes("password"), problem: "grant_types[0]"},
		{name: "grant type listed twice", registry: withGrantTypes("authorization_code", "authorization_code"), problem: "grant_types[1]"},
		{name: "empty grant types", registry: withGrantTypes([]string{}...), problem: "grant_types"},
		{name: "authorization_code alone", registry: withGrantTypes("authorization_code"), problem: "grant_types"},
		{name: "refresh_token alone", registry: withGrantTypes("refresh_token"), problem: "grant_types"},
		{name: "scope on a Client of the code flow", registry: registryWithResourceServers(t, []entry{ordersServer()}, []entry{with(with(secretClient(), "resource_servers", []string{"https://api.example/orders"}), "scope", "orders:read")}), problem: "scope is allowed only for client_credentials"},
		{name: "machine client also for authorization_code", registry: withMachine("grant_types", []string{"client_credentials", "authorization_code"}), problem: "alone"},
		{name: "machine client also for refresh_token", registry: withMachine("grant_types", []string{"refresh_token", "client_credentials"}), problem: "alone"},
		{name: "public machine client", registry: registryWithResourceServers(t, []entry{ordersServer()}, []entry{with(with(machineClient(), "client_secret_hash", nil), "token_endpoint_auth_method", "none")}), problem: "confidential"},
		{name: "machine client with redirect URIs", registry: withMachine("redirect_uris", []string{"https://rp.example/callback"}), problem: "redirect_uris is not allowed"},
		{name: "machine client with post-logout redirect URIs", registry: withMachine("post_logout_redirect_uris", []string{"https://rp.example/signed-out"}), problem: "post_logout_redirect_uris is not allowed"},
		{name: "machine client whose client_id is a UUID", registry: withMachine("client_id", "7c9e6679-7425-40de-944b-e07fc1f90ae7"), problem: "is a UUID"},
		{name: "machine client whose client_id is an uppercase UUID", registry: withMachine("client_id", "7C9E6679-7425-40DE-944B-E07FC1F90AE7"), problem: "is a UUID"},
		{name: "code-flow client whose client_id is a UUID", registry: registryJSON(t, []entry{with(secretClient(), "client_id", "7c9e6679-7425-40de-944b-e07fc1f90ae7")}, nil), problem: "is a UUID"},
		{name: "public client whose client_id is a mixed-case UUID", registry: registryJSON(t, []entry{with(publicClient, "client_id", "7c9e6679-7425-40DE-944b-e07fc1f90ae7")}, nil), problem: "is a UUID"},
		{name: "machine client without scope", registry: withMachine("scope", nil), problem: "scope is required"},
		{name: "machine client with empty scope", registry: withMachine("scope", ""), problem: "scope is required"},
		{name: "machine client with a scope of a Resource Server not listed", registry: withMachine("scope", "orders:read billing:read"), problem: `"billing:read"`},
		{name: "machine client with an unknown scope", registry: withMachine("scope", "orders:write"), problem: `"orders:write"`},
		{name: "machine client with openid", registry: withMachine("scope", "openid"), problem: `"openid"`},
		{name: "machine client with a scope listed twice", registry: withMachine("scope", "orders:read orders:read"), problem: "listed twice"},
		{name: "machine client with scopes separated by two spaces", registry: withMachine("scope", "orders:read  orders:read"), problem: "single spaces"},
		{name: "machine client with a leading space", registry: withMachine("scope", " orders:read"), problem: "single spaces"},
		{name: "machine client with a scope that is not a scope-token", registry: withMachine("scope", `orders"read`), problem: "RFC 6749"},
		{name: "machine client without Resource Servers", registry: withMachine("resource_servers", nil), problem: `"orders:read"`},
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
// REQ-OAUTH-1, REQ-CORE-1, REQ-LOGOUT-10, REQ-RESOURCE-1, REQ-AT-5: the
// forms the refusals above allow. A Resource Server's identifier may be a
// URN, or have a query, which RFC 8707 §2 discourages without forbidding.
// It may differ from the issuer by a trailing slash alone, since UserInfo
// compares aud with the issuer as strings, and refuses its tokens.
// REQ-CLIENTMETA-1, REQ-CLIENTMETA-2: a Client may list
// authorization_code and refresh_token, in either order, as it may leave
// grant_types out; a machine Client, by any confidential method, lists
// scopes of each Resource Server it may request. A client_id may be a
// UUID's 32 hexadecimal digits without hyphens, which is not a UUID's
// form, and so no Subject's.
func TestRunAcceptsRegistry(t *testing.T) {
	t.Parallel()

	// Not cryptotest.SetGlobalRandom, as in TestRunRefusesRegistry.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwtClient := with(with(with(secretClient(), "client_secret_hash", nil), "token_endpoint_auth_method", "private_key_jwt"), "client_id", "jwt")
	jwtClient["jwks"] = jwks(t, &ecKey.PublicKey)
	b, err := json.Marshal(map[string]any{
		"resource_servers": []entry{
			ordersServer(),
			{"identifier": "urn:example:billing", "scopes": []entry{
				{"scope": "billing:read", "description": "read your invoices"},
				{"scope": "https://api.example/billing.write", "description": "pay your invoices"},
			}},
			{"identifier": "https://api.example/reports?tenant=a", "scopes": []entry{{"scope": "reports", "description": "read your reports"}}},
			{"identifier": loopbackIssuer + "/", "scopes": []entry{{"scope": "local", "description": "use the local service"}}},
		},
		"clients": []entry{
			with(secretClient(), "resource_servers", []string{"https://api.example/orders", "urn:example:billing"}),
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
			with(with(secretClient(), "client_id", "listed"), "grant_types", []string{"refresh_token", "authorization_code"}),
			with(with(machineClient(), "resource_servers", []string{"https://api.example/orders", "urn:example:billing"}), "scope", "orders:read https://api.example/billing.write"),
			with(with(with(with(machineClient(), "client_id", "7c9e6679742540de944be07fc1f90ae7"), "client_secret_hash", nil), "token_endpoint_auth_method", "private_key_jwt"), "jwks", jwks(t, &ecKey.PublicKey)),
		},
		"end_users": []entry{
			with(endUser(), "claims", map[string]any{
				"name":           "Alice Example",
				"email":          "alice@example.com",
				"email_verified": true,
				"address":        map[string]any{"country": "NZ"},
				"updated_at":     1700000000,
			}),
			with(with(endUser(), "sub", "0b5c3c62-1f3e-4f2b-9f43-8c1d2e3f4a5b"), "username", "Alice"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	p := start(t, map[string]string{
		"PULSAR_ISSUER":       loopbackIssuer,
		"PULSAR_DATABASE_URL": postgrestest.NewDatabase(t),
		"PULSAR_REGISTRY":     writeRegistry(t, string(b)),
	})
	p.waitListening()
	p.waitKeysLoaded()
	if err := p.stop(); err != nil {
		t.Errorf("run() = %v, want nil after cancellation", err)
	}
}
