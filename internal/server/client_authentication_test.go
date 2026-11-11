package server

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"

	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
)

// The redirect URIs that the Clients post and jwt registered in
// flowRegistry.
const (
	postRedirectURI = "https://post.example/callback"
	jwtRedirectURI  = "https://jwt.example/callback"
)

// jwtBearer is the client_assertion_type of a JWT that authenticates a
// Client (RFC 7523 §2.2).
const jwtBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" //nolint:gosec // G101: a URN that names a format, not a credential.

// clientKey is a private key of the private_key_jwt Client jwt, with the
// kid and the one algorithm it is registered for.
type clientKey struct {
	kid string
	alg jose.SignatureAlgorithm
	key crypto.Signer
}

// jwtKeys returns jwt's keys: one for each algorithm pulsar allows. They
// are generated once, since RSA keys are slow to generate; their values do
// not matter, so the tests share them.
var jwtKeys = sync.OnceValue(func() []clientKey {
	rs, errRS := rsa.GenerateKey(rand.Reader, 2048)
	ps, errPS := rsa.GenerateKey(rand.Reader, 2048)
	es, errES := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := errors.Join(errRS, errPS, errES); err != nil {
		panic(err)
	}
	return []clientKey{
		{kid: "rs", alg: jose.RS256, key: rs},
		{kid: "ps", alg: jose.PS256, key: ps},
		{kid: "es", alg: jose.ES256, key: es},
	}
})

// jwtKey returns jwt's key for alg.
func jwtKey(alg jose.SignatureAlgorithm) clientKey {
	i := slices.IndexFunc(jwtKeys(), func(k clientKey) bool { return k.alg == alg })
	if i < 0 {
		panic("jwt has no key for " + string(alg))
	}
	return jwtKeys()[i]
}

// jwtJWKS returns the JWK Set that jwt registers: the public keys of
// jwtKeys, each with its kid and alg.
func jwtJWKS(tb testing.TB) string {
	tb.Helper()
	var set jose.JSONWebKeySet
	for _, k := range jwtKeys() {
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: k.key.Public(), KeyID: k.kid, Algorithm: string(k.alg), Use: "sig"})
	}
	b, err := json.Marshal(set)
	if err != nil {
		tb.Fatal(err)
	}
	return string(b)
}

// clientParams returns the parameters of a valid authorization request
// from clientID, for redirectURI.
func clientParams(clientID, redirectURI string) url.Values {
	params := authorizationParams()
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	return params
}

// postTokenRequest sends a token request with form, with no Authorization
// header: whatever authenticates the Client is in form.
func postTokenRequest(t *testing.T, handler http.Handler, form url.Values) response {
	t.Helper()
	return tokenRequest(t, handler, "", "", form)
}

// idTokenAudience returns the aud of the ID token in a successful token
// response, failing the test for any other response.
func idTokenAudience(t *testing.T, handler http.Handler, resp response) any {
	t.Helper()
	if resp.status != http.StatusOK {
		t.Fatalf("POST %s status = %d, want %d; body %q", tokenPath, resp.status, http.StatusOK, resp.body)
	}
	var tokens struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal([]byte(resp.body), &tokens); err != nil {
		t.Fatalf("POST %s body is not a token response: %v", tokenPath, err)
	}
	return verify(t, handler, tokens.IDToken).claims["aud"]
}

// REQ-OAUTH-25: a Client registered for client_secret_post redeems its code
// with its client_id and secret in the request body.
func TestTokenClientSecretPost(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code(t, handler, clientParams("post", postRedirectURI))},
		"redirect_uri":  {postRedirectURI},
		"client_id":     {"post"},
		"client_secret": {postSecret},
	}
	if got := idTokenAudience(t, handler, postTokenRequest(t, handler, form)); got != "post" {
		t.Errorf("POST %s ID token aud = %v, want %q", tokenPath, got, "post")
	}
}

// tokenErrorCode returns the error code of a token error response,
// failing the test unless the response has status and the headers of RFC 6749 §5.2.
func tokenErrorCode(t *testing.T, resp response, status int) string {
	t.Helper()
	return jsonErrorCode(t, tokenPath, resp, status)
}

// jsonErrorCode returns the error code of an error response in the JSON
// form of RFC 6749 §5.2 from the endpoint at path, failing the test unless
// the response has status and the headers of RFC 6749 §5.2.
func jsonErrorCode(t *testing.T, path string, resp response, status int) string {
	t.Helper()
	if resp.status != status {
		t.Errorf("POST %s status = %d, want %d; body %q", path, resp.status, status, resp.body)
	}
	wantHeader := map[string]string{"Content-Type": "application/json", "Cache-Control": "no-store", "Pragma": "no-cache"}
	if status == http.StatusUnauthorized {
		wantHeader["WWW-Authenticate"] = `Basic realm="` + loginIssuer + `"`
	}
	if diff := cmp.Diff(wantHeader, headers(resp.header, wantHeader)); diff != "" {
		t.Errorf("POST %s headers mismatch (-want +got):\n%s", path, diff)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(resp.body), &body); err != nil {
		t.Fatalf("POST %s body %q is not JSON: %v", path, resp.body, err)
	}
	return body.Error
}

// credentials are a client_id and secret.
type credentials struct {
	id, secret string
}

// REQ-OAUTH-24, REQ-OAUTH-25, REQ-OAUTH-26, REQ-ASSERT-2: a Client that
// authenticates by a method other than the one it registered, or by more
// than one, fails; with invalid_client, unless the methods are HTTP Basic
// and the request body, which RFC 6749 §5.2 makes invalid_request.
func TestTokenClientAuthenticationMethod(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	tests := []struct {
		name        string
		clientID    string // the Client the code is issued to
		redirectURI string
		basic       credentials // of HTTP Basic authentication, if any
		query       url.Values
		body        url.Values
		wantStatus  int
		wantError   string
	}{
		{
			name: "client_secret_basic Client by the body", clientID: "rp", redirectURI: rpRedirectURI,
			body:       url.Values{"client_id": {"rp"}, "client_secret": {rpSecret}},
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		{
			name: "client_secret_post Client by Basic", clientID: "post", redirectURI: postRedirectURI,
			basic:      credentials{"post", postSecret},
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		{
			name: "client_secret_post Client with a wrong secret", clientID: "post", redirectURI: postRedirectURI,
			body:       url.Values{"client_id": {"post"}, "client_secret": {rpSecret}},
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		{
			name: "client_secret_post Client without client_id", clientID: "post", redirectURI: postRedirectURI,
			body:       url.Values{"client_secret": {postSecret}},
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		{
			name: "client_secret_post credentials in the request URI", clientID: "post", redirectURI: postRedirectURI,
			query:      url.Values{"client_id": {"post"}, "client_secret": {postSecret}},
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		{
			name: "private_key_jwt Client by the body", clientID: "jwt", redirectURI: jwtRedirectURI,
			body:       url.Values{"client_id": {"jwt"}, "client_secret": {postSecret}},
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		{
			name: "Basic and the body", clientID: "post", redirectURI: postRedirectURI,
			basic:      credentials{"post", postSecret},
			body:       url.Values{"client_id": {"post"}, "client_secret": {postSecret}},
			wantStatus: http.StatusBadRequest, wantError: "invalid_request",
		},
		{
			name: "Basic and an assertion", clientID: "rp", redirectURI: rpRedirectURI,
			basic:      credentials{"rp", rpSecret},
			body:       url.Values{"client_assertion_type": {jwtBearer}, "client_assertion": {"x"}},
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		{
			name: "Basic and an assertion without its type", clientID: "rp", redirectURI: rpRedirectURI,
			basic:      credentials{"rp", rpSecret},
			body:       url.Values{"client_assertion": {"x"}},
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		{
			name: "the body and an assertion", clientID: "post", redirectURI: postRedirectURI,
			body:       url.Values{"client_id": {"post"}, "client_secret": {postSecret}, "client_assertion_type": {jwtBearer}},
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			form := url.Values{
				"grant_type":   {"authorization_code"},
				"code":         {code(t, handler, clientParams(tt.clientID, tt.redirectURI))},
				"redirect_uri": {tt.redirectURI},
			}
			maps.Copy(form, tt.body)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://op.example"+tokenPath+"?"+tt.query.Encode(), strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tt.basic.id != "" {
				req.SetBasicAuth(url.QueryEscape(tt.basic.id), url.QueryEscape(tt.basic.secret))
			}
			resp := (&browser{t: t, handler: handler}).do(req)
			if got := tokenErrorCode(t, resp, tt.wantStatus); got != tt.wantError {
				t.Errorf("POST %s error = %q, want %q", tokenPath, got, tt.wantError)
			}
		})
	}
}

// tokenEndpoint is the token endpoint URL of the OP at loginIssuer.
const tokenEndpoint = loginIssuer + "/token"

// assertionClaims returns the claims of a valid client assertion from jwt,
// for the OP at loginIssuer, expiring a minute from now.
func assertionClaims() map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": "jwt",
		"sub": "jwt",
		"aud": loginIssuer,
		"exp": now.Add(time.Minute).Unix(),
		"iat": now.Unix(),
		"jti": rand.Text(),
	}
}

// signJWS returns a JWS of claims, signed with key by alg, whose header
// names kid unless it is "", and typ unless it is "".
func signJWS(tb testing.TB, alg jose.SignatureAlgorithm, key any, kid, typ string, claims map[string]any) *jose.JSONWebSignature {
	tb.Helper()
	opts := &jose.SignerOptions{}
	if typ != "" {
		opts = opts.WithType(jose.ContentType(typ))
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{Key: key, KeyID: kid}}, opts)
	if err != nil {
		tb.Fatalf("jose.NewSigner(%s) error = %v", alg, err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		tb.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		tb.Fatalf("Sign() error = %v", err)
	}
	return jws
}

// signAssertion returns signJWS's JWS, without typ, in the compact
// serialization: a JWT.
func signAssertion(tb testing.TB, alg jose.SignatureAlgorithm, key any, kid string, claims map[string]any) string {
	tb.Helper()
	s, err := signJWS(tb, alg, key, kid, "", claims).CompactSerialize()
	if err != nil {
		tb.Fatal(err)
	}
	return s
}

// jwtForm returns the form of a token request that redeems code for jwt,
// authenticated by assertion.
func jwtForm(code, assertion string) url.Values {
	return url.Values{
		"grant_type":            {"authorization_code"},
		"code":                  {code},
		"redirect_uri":          {jwtRedirectURI},
		"client_assertion_type": {jwtBearer},
		"client_assertion":      {assertion},
	}
}

// REQ-JWTAUTH-1, REQ-JWTAUTH-2, REQ-JWTAUTH-3, REQ-JWTAUTH-4,
// REQ-JWTAUTH-7, REQ-ASSERT-1, REQ-ASSERTAUD-1, REQ-CORE-31, REQ-CORE-32,
// REQ-CORE-34, REQ-JWTBCP-2: a Client registered for private_key_jwt
// redeems its code with an assertion signed by any of its keys, by the
// key's algorithm, whose sole audience is the issuer, as a string or an
// array of one, with or without typ.
func TestTokenPrivateKeyJWT(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	rs, ps, es := jwtKey(jose.RS256), jwtKey(jose.PS256), jwtKey(jose.ES256)
	tests := []struct {
		name string
		key  clientKey
		kid  string // the header's kid
		typ  string // the header's typ
		edit func(claims map[string]any, form url.Values)
	}{
		{name: "RS256", key: rs, kid: rs.kid},
		{name: "PS256", key: ps, kid: ps.kid},
		{name: "ES256", key: es, kid: es.kid},
		{name: "no kid", key: es},
		{name: "aud an array of the issuer alone", key: rs, kid: rs.kid, edit: func(c map[string]any, _ url.Values) { c["aud"] = []string{loginIssuer} }},
		{name: "typ client-authentication+jwt", key: rs, kid: rs.kid, typ: "client-authentication+jwt"},
		{name: "typ JWT", key: rs, kid: rs.kid, typ: "JWT"},
		{name: "no iat", key: rs, kid: rs.kid, edit: func(c map[string]any, _ url.Values) { delete(c, "iat") }},
		{name: "nbf now", key: rs, kid: rs.kid, edit: func(c map[string]any, _ url.Values) { c["nbf"] = time.Now().Unix() }},
		{name: "claims pulsar does not know", key: rs, kid: rs.kid, edit: func(c map[string]any, _ url.Values) { c["x-unknown"] = true }},
		{name: "client_id in the body", key: rs, kid: rs.kid, edit: func(_ map[string]any, f url.Values) { f.Set("client_id", "jwt") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			claims := assertionClaims()
			form := url.Values{}
			if tt.edit != nil {
				tt.edit(claims, form)
			}
			c := code(t, handler, clientParams("jwt", jwtRedirectURI))
			assertion, err := signJWS(t, tt.key.alg, tt.key.key, tt.kid, tt.typ, claims).CompactSerialize()
			if err != nil {
				t.Fatal(err)
			}
			maps.Copy(form, jwtForm(c, assertion))
			if got := idTokenAudience(t, handler, postTokenRequest(t, handler, form)); got != "jwt" {
				t.Errorf("POST %s ID token aud = %v, want %q", tokenPath, got, "jwt")
			}
		})
	}
}

// REQ-DISC-10, REQ-JWTBCP-2: an assertion authenticates by exactly the
// algorithms discovery lists. Each listed one does, with jwt's key for it;
// every other algorithm pulsar's JOSE library signs with, with a key of
// the type it takes under one of jwt's kids, does not.
func TestDiscoveryAssertionAlgorithms(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://op.example/tenant/.well-known/openid-configuration", http.NoBody))
	var metadata struct {
		Algs []jose.SignatureAlgorithm `json:"token_endpoint_auth_signing_alg_values_supported"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &metadata); err != nil {
		t.Fatalf("GET discovery document body is not JSON: %v", err)
	}

	rs, ps, es := jwtKey(jose.RS256), jwtKey(jose.PS256), jwtKey(jose.ES256)
	p384, errP384 := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p521, errP521 := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	_, ed, errEd := ed25519.GenerateKey(rand.Reader)
	if err := errors.Join(errP384, errP521, errEd); err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte("k"), 64) // the least HS512 takes, and enough for HS256 and HS384
	tests := []struct {
		alg jose.SignatureAlgorithm
		key any
		kid string
	}{
		{alg: jose.RS256, key: rs.key, kid: rs.kid},
		{alg: jose.RS384, key: rs.key, kid: rs.kid},
		{alg: jose.RS512, key: rs.key, kid: rs.kid},
		{alg: jose.PS256, key: ps.key, kid: ps.kid},
		{alg: jose.PS384, key: ps.key, kid: ps.kid},
		{alg: jose.PS512, key: ps.key, kid: ps.kid},
		{alg: jose.ES256, key: es.key, kid: es.kid},
		{alg: jose.ES384, key: p384, kid: es.kid},
		{alg: jose.ES512, key: p521, kid: es.kid},
		{alg: jose.EdDSA, key: ed, kid: es.kid},
		{alg: jose.HS256, key: secret, kid: rs.kid},
		{alg: jose.HS384, key: secret, kid: rs.kid},
		{alg: jose.HS512, key: secret, kid: rs.kid},
	}
	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			t.Parallel()
			form := jwtForm(code(t, handler, clientParams("jwt", jwtRedirectURI)), signAssertion(t, tt.alg, tt.key, tt.kid, assertionClaims()))
			resp := postTokenRequest(t, handler, form)
			if !slices.Contains(metadata.Algs, tt.alg) {
				if got := tokenErrorCode(t, resp, http.StatusUnauthorized); got != "invalid_client" {
					t.Errorf("POST %s with an assertion by %s, which discovery does not list: error = %q, want %q", tokenPath, tt.alg, got, "invalid_client")
				}
				return
			}
			if got := idTokenAudience(t, handler, resp); got != "jwt" {
				t.Errorf("POST %s ID token aud = %v, want %q", tokenPath, got, "jwt")
			}
		})
	}
}

// unsigned returns a JWT with claims and the alg none, unsigned.
func unsigned(tb testing.TB, claims map[string]any) string {
	tb.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		tb.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc(payload) + "."
}

// REQ-JWTAUTH-1, REQ-JWTAUTH-2, REQ-JWTAUTH-3, REQ-JWTAUTH-4,
// REQ-JWTAUTH-5, REQ-JWTAUTH-7, REQ-JWTAUTH-8, REQ-ASSERT-1, REQ-ASSERT-2,
// REQ-ASSERTAUD-1, REQ-ASSERTAUD-2, REQ-CORE-31, REQ-CORE-32, REQ-CORE-33,
// REQ-CORE-34, REQ-CORE-35, REQ-JWTBCP-1, REQ-JWTBCP-2, REQ-JWTBCP-3,
// REQ-DISC-10: a client assertion fails with invalid_client unless it is
// one JWT, signed by a key jwt registered, with that key's algorithm,
// naming jwt as its issuer and subject and the OP's issuer, compared as a
// string, as its sole audience, not its token endpoint URL, with a jti,
// and with an exp that has not passed and is at most an hour away.
func TestTokenPrivateKeyJWTRejected(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	rs, ps, es := jwtKey(jose.RS256), jwtKey(jose.PS256), jwtKey(jose.ES256)
	unregistered, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// sign signs claims with rs, as jwt registered it.
	sign := func(claims map[string]any) string {
		return signAssertion(t, rs.alg, rs.key, rs.kid, claims)
	}
	// with returns assertionClaims with name set to value, or removed if
	// value is nil.
	with := func(name string, value any) map[string]any {
		c := assertionClaims()
		if value == nil {
			delete(c, name)
		} else {
			c[name] = value
		}
		return c
	}
	confidential := assertionClaims()
	confidential["iss"], confidential["sub"] = "rp", "rp"
	now := time.Now()
	// The assertions are signed before any subtest runs, and expire a
	// minute later, long after the last subtest.
	tests := []struct {
		name      string
		assertion string
		edit      func(form url.Values) // edits the form after the assertion is set
	}{
		{name: "an unregistered key under a registered kid", assertion: signAssertion(t, jose.RS256, unregistered, rs.kid, assertionClaims())},
		{name: "an unregistered key without kid", assertion: signAssertion(t, jose.RS256, unregistered, "", assertionClaims())},
		{name: "a registered key under a kid jwt did not register", assertion: signAssertion(t, jose.ES256, es.key, "unknown", assertionClaims())},
		{name: "alg none", assertion: unsigned(t, assertionClaims())},
		{name: "alg HS256", assertion: signAssertion(t, jose.HS256, []byte("a secret of 32 bytes, as HS256 w"), rs.kid, assertionClaims())},
		{name: "alg RS384, not allowed", assertion: signAssertion(t, jose.RS384, rs.key, rs.kid, assertionClaims())},
		{name: "PS256 with the RS256 key", assertion: signAssertion(t, jose.PS256, rs.key, rs.kid, assertionClaims())},
		{name: "RS256 with the PS256 key", assertion: signAssertion(t, jose.RS256, ps.key, ps.kid, assertionClaims())},
		{name: "iss another Client", assertion: sign(with("iss", "rp"))},
		{name: "iss in another case", assertion: sign(with("iss", "JWT"))},
		{name: "no iss", assertion: sign(with("iss", nil))},
		{name: "sub another Client", assertion: sign(with("sub", "post"))},
		{name: "no sub", assertion: sign(with("sub", nil))},
		{name: "iss and sub a client_secret_basic Client", assertion: sign(confidential)},
		{name: "aud another server", assertion: sign(with("aud", "https://other.example/token"))},
		{name: "aud the token endpoint", assertion: sign(with("aud", tokenEndpoint))},
		{name: "aud an array of the token endpoint alone", assertion: sign(with("aud", []string{tokenEndpoint}))},
		{name: "aud an array of the issuer and the token endpoint", assertion: sign(with("aud", []string{loginIssuer, tokenEndpoint}))},
		{name: "aud an array of another server and the issuer", assertion: sign(with("aud", []string{"https://other.example", loginIssuer}))},
		{name: "aud an empty array", assertion: sign(with("aud", []string{}))},
		{name: "aud null", assertion: sign(with("aud", json.RawMessage("null")))},
		{name: "aud an array of the issuer and a number", assertion: sign(with("aud", []any{loginIssuer, 1}))},
		{name: "aud the issuer with a slash", assertion: sign(with("aud", loginIssuer+"/"))},
		{name: "aud the issuer in another case", assertion: sign(with("aud", strings.ToUpper(loginIssuer)))},
		{name: "aud the authorization endpoint", assertion: sign(with("aud", loginIssuer+"/authorize"))},
		{name: "no aud", assertion: sign(with("aud", nil))},
		{name: "no exp", assertion: sign(with("exp", nil))},
		{name: "exp now", assertion: sign(with("exp", now.Unix()))},
		{name: "exp passed", assertion: sign(with("exp", now.Add(-time.Minute).Unix()))},
		{name: "exp more than an hour away", assertion: sign(with("exp", now.Add(time.Hour+time.Minute).Unix()))},
		{name: "exp not a number", assertion: sign(with("exp", "soon"))},
		{name: "nbf more than a minute away", assertion: sign(with("nbf", now.Add(2*time.Minute).Unix()))},
		{name: "no jti", assertion: sign(with("jti", nil))},
		{name: "client_id another Client", assertion: sign(assertionClaims()), edit: func(f url.Values) { f.Set("client_id", "post") }},
		{
			name:      "client_assertion_type another type",
			assertion: sign(assertionClaims()),
			edit: func(f url.Values) {
				f.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:saml2-bearer")
			},
		},
		{name: "no client_assertion_type", assertion: sign(assertionClaims()), edit: func(f url.Values) { f.Del("client_assertion_type") }},
		{name: "no client_assertion", edit: func(f url.Values) { f.Del("client_assertion") }},
		{name: "not a JWT", assertion: "not a JWT"},
		{name: "two JWTs", assertion: sign(assertionClaims()) + " " + sign(assertionClaims())},
		{name: "the JWS JSON serialization", assertion: signJWS(t, rs.alg, rs.key, rs.kid, "", assertionClaims()).FullSerialize()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			form := jwtForm(code(t, handler, clientParams("jwt", jwtRedirectURI)), tt.assertion)
			if tt.edit != nil {
				tt.edit(form)
			}
			if got := tokenErrorCode(t, postTokenRequest(t, handler, form), http.StatusUnauthorized); got != "invalid_client" {
				t.Errorf("POST %s error = %q, want %q", tokenPath, got, "invalid_client")
			}
		})
	}
}

// REQ-JWTAUTH-5: an assertion whose nbf is up to a minute ahead of
// pulsar's clock, for clock skew between the Client and pulsar,
// authenticates; one whose nbf is further ahead does not.
func TestTokenPrivateKeyJWTNotBefore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		ahead      time.Duration
		wantStatus int
	}{
		{ahead: time.Minute, wantStatus: http.StatusOK},
		{ahead: time.Minute + time.Second, wantStatus: http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.ahead.String(), func(t *testing.T) {
			t.Parallel()
			databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
			synctest.Test(t, func(t *testing.T) {
				handler := newBubbleFlowHandler(t, databaseURL)
				k := jwtKey(jose.RS256)
				claims := assertionClaims()
				claims["nbf"] = time.Now().Add(tt.ahead).Unix()
				claims["exp"] = time.Now().Add(tt.ahead + time.Minute).Unix()
				form := jwtForm(code(t, handler, clientParams("jwt", jwtRedirectURI)), signAssertion(t, k.alg, k.key, k.kid, claims))
				if resp := postTokenRequest(t, handler, form); resp.status != tt.wantStatus {
					t.Errorf("POST %s with nbf %v ahead status = %d, want %d; body %q", tokenPath, tt.ahead, resp.status, tt.wantStatus, resp.body)
				}
			})
		})
	}
}

// REQ-OAUTH-15: a token request that lacks a parameter fails with
// invalid_request before its Client authenticates, so a client assertion
// sent with it is not used up and authenticates the corrected request.
func TestTokenMalformedRequestKeepsAssertion(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	k := jwtKey(jose.RS256)
	assertion := signAssertion(t, k.alg, k.key, k.kid, assertionClaims())
	form := jwtForm(code(t, handler, clientParams("jwt", jwtRedirectURI)), assertion)
	malformed := maps.Clone(form)
	malformed.Del("code")
	if got := tokenErrorCode(t, postTokenRequest(t, handler, malformed), http.StatusBadRequest); got != "invalid_request" {
		t.Errorf("POST %s without code error = %q, want %q", tokenPath, got, "invalid_request")
	}
	if got := idTokenAudience(t, handler, postTokenRequest(t, handler, form)); got != "jwt" {
		t.Errorf("POST %s ID token aud = %v, want %q", tokenPath, got, "jwt")
	}
}

// REQ-JWTAUTH-4, REQ-JWTAUTH-6, REQ-CORE-33, REQ-CORE-34: an assertion
// authenticates once, and not at or after its exp. Its jti is refused,
// even in a new assertion, until the assertion that first used it
// expires, and not after.
func TestTokenPrivateKeyJWTReplay(t *testing.T) {
	t.Parallel()

	databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
	synctest.Test(t, func(t *testing.T) {
		handler := newBubbleFlowHandler(t, databaseURL)
		k := jwtKey(jose.RS256)
		// redeem redeems a new code for jwt with assertion.
		redeem := func(assertion string) response {
			return postTokenRequest(t, handler, jwtForm(code(t, handler, clientParams("jwt", jwtRedirectURI)), assertion))
		}

		first := assertionClaims() // exp a minute from now
		first["jti"] = "reused"
		assertion := signAssertion(t, k.alg, k.key, k.kid, first)
		if resp := redeem(assertion); resp.status != http.StatusOK {
			t.Fatalf("POST %s with a new assertion status = %d, want %d; body %q", tokenPath, resp.status, http.StatusOK, resp.body)
		}

		time.Sleep(30 * time.Second)
		if got := tokenErrorCode(t, redeem(assertion), http.StatusUnauthorized); got != "invalid_client" {
			t.Errorf("POST %s with the assertion again error = %q, want %q", tokenPath, got, "invalid_client")
		}

		second := assertionClaims()
		second["jti"] = "reused"
		second["exp"] = time.Now().Add(time.Minute).Unix()
		later := signAssertion(t, k.alg, k.key, k.kid, second)
		time.Sleep(29 * time.Second)
		if got := tokenErrorCode(t, redeem(later), http.StatusUnauthorized); got != "invalid_client" {
			t.Errorf("POST %s with the jti 59s into the first assertion's minute error = %q, want %q", tokenPath, got, "invalid_client")
		}

		// The first assertion's exp: it is refused for that alone, since
		// its jti is no longer kept.
		time.Sleep(time.Second)
		if got := tokenErrorCode(t, redeem(assertion), http.StatusUnauthorized); got != "invalid_client" {
			t.Errorf("POST %s with the first assertion at its exp error = %q, want %q", tokenPath, got, "invalid_client")
		}
		if resp := redeem(later); resp.status != http.StatusOK {
			t.Errorf("POST %s with the jti once the first assertion expired status = %d, want %d; body %q", tokenPath, resp.status, http.StatusOK, resp.body)
		}
	})
}

// REQ-JWTAUTH-6, REQ-CORE-33: of token requests that present one assertion
// at once, each with its own code, at most one authenticates.
func TestTokenPrivateKeyJWTConcurrentReplay(t *testing.T) {
	t.Parallel()

	const requests = 8
	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	k := jwtKey(jose.RS256)
	assertion := signAssertion(t, k.alg, k.key, k.kid, assertionClaims())
	forms := make([]url.Values, requests)
	for i := range forms {
		forms[i] = jwtForm(code(t, handler, clientParams("jwt", jwtRedirectURI)), assertion)
	}
	statuses := make([]int, requests)
	var wg sync.WaitGroup
	for i := range requests {
		wg.Go(func() {
			statuses[i] = postTokenRequest(t, handler, forms[i]).status
		})
	}
	wg.Wait()
	counts := map[int]int{}
	for _, s := range statuses {
		counts[s]++
	}
	want := map[int]int{http.StatusOK: 1, http.StatusUnauthorized: requests - 1}
	if diff := cmp.Diff(want, counts); diff != "" {
		t.Errorf("statuses of %d concurrent requests with one assertion mismatch (-want +got):\n%s", requests, diff)
	}
}

// verifiesWithJWTKey reports whether raw is a JWS in the compact
// serialization that one of jwtKeys verifies, by the algorithm it is
// registered for, whatever its claims: the least an assertion must be to
// authenticate jwt.
func verifiesWithJWTKey(raw string) bool {
	for _, k := range jwtKeys() {
		jws, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{k.alg})
		if err == nil {
			if _, err := jws.Verify(k.key.Public()); err == nil {
				return true
			}
		}
	}
	return false
}

// REQ-JWTAUTH-7, REQ-JWTAUTH-8, REQ-ASSERT-2: whatever a client assertion
// holds, the token endpoint answers invalid_client, or, if it accepted the
// assertion, invalid_grant for the unknown code; it accepts only an
// assertion that one of jwt's keys verifies, and never fails itself.
func FuzzClientAssertion(f *testing.F) {
	k := jwtKey(jose.RS256)
	valid := signAssertion(f, k.alg, k.key, k.kid, assertionClaims())
	parts := strings.Split(valid, ".")
	f.Add(valid)
	f.Add(unsigned(f, assertionClaims()))
	f.Add(signAssertion(f, jose.HS256, []byte("a secret of 32 bytes, as HS256 w"), k.kid, assertionClaims()))
	f.Add(parts[0] + "." + parts[1] + ".")
	f.Add(parts[0] + ".." + parts[2])
	f.Add(valid + "." + parts[2])
	f.Add(`{"payload":"e30","signatures":[]}`)
	f.Add("e30.e30.e30")
	f.Add("..")
	f.Add("")

	handler := newFlowHandler(f, postgrestest.Open(f, postgrestest.NewDatabase(f)))
	f.Fuzz(func(t *testing.T, raw string) {
		form := jwtForm("unknown", raw)
		resp := postTokenRequest(t, handler, form)
		var body struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal([]byte(resp.body), &body); err != nil {
			t.Fatalf("POST %s with client_assertion %q: body %q is not JSON: %v", tokenPath, raw, resp.body, err)
		}
		switch {
		case resp.status == http.StatusUnauthorized && body.Error == "invalid_client":
		case resp.status == http.StatusBadRequest && body.Error == "invalid_grant":
			if !verifiesWithJWTKey(raw) {
				t.Errorf("POST %s with client_assertion %q authenticated jwt, though none of its keys verifies it", tokenPath, raw)
			}
		default:
			t.Errorf("POST %s with client_assertion %q = %d %q, want %d invalid_client or %d invalid_grant", tokenPath, raw, resp.status, body.Error, http.StatusUnauthorized, http.StatusBadRequest)
		}
	})
}

// REQ-OAUTH-44: failed attempts to authenticate as a Client are not
// counted against it, so that no one who knows its client_id, which is
// public, can hold up its token requests: after many with a wrong secret,
// by either method, it still authenticates with its own.
func TestTokenClientSecretNotThrottled(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	tests := []struct {
		name        string
		clientID    string
		redirectURI string
		wrong       func() response
		right       func(code string) response
	}{
		{
			name:        "client_secret_basic",
			clientID:    "rp",
			redirectURI: rpRedirectURI,
			wrong: func() response {
				return tokenRequest(t, handler, "rp", "wrong", codeForm("unknown"))
			},
			right: func(code string) response {
				return tokenRequest(t, handler, "rp", rpSecret, codeForm(code))
			},
		},
		{
			name:        "client_secret_post",
			clientID:    "post",
			redirectURI: postRedirectURI,
			wrong: func() response {
				return postTokenRequest(t, handler, url.Values{
					"grant_type": {"authorization_code"}, "code": {"unknown"}, "redirect_uri": {postRedirectURI},
					"client_id": {"post"}, "client_secret": {"wrong"},
				})
			},
			right: func(code string) response {
				return postTokenRequest(t, handler, url.Values{
					"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {postRedirectURI},
					"client_id": {"post"}, "client_secret": {postSecret},
				})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for i := range 20 {
				if got := tokenErrorCode(t, tt.wrong(), http.StatusUnauthorized); got != "invalid_client" {
					t.Fatalf("POST %s with a wrong secret, number %d: error = %q, want %q", tokenPath, i+1, got, "invalid_client")
				}
			}
			if got := idTokenAudience(t, handler, tt.right(code(t, handler, clientParams(tt.clientID, tt.redirectURI)))); got != tt.clientID {
				t.Errorf("POST %s after 20 wrong secrets: ID token aud = %v, want %q", tokenPath, got, tt.clientID)
			}
		})
	}
}
