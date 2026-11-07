package server

import (
	"encoding/json"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palebluedot4/pulsar/internal/config"
	"github.com/palebluedot4/pulsar/internal/oidc"
	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
	"github.com/palebluedot4/pulsar/internal/registry"
	"github.com/palebluedot4/pulsar/internal/signing"
)

// Paths of the endpoints under loginIssuer.
const (
	authorizationPath = "/tenant/authorize"
	tokenPath         = "/tenant/token"
	jwksPath          = "/tenant/jwks"
)

// The Clients the tests act as. rp's secret holds characters that HTTP
// Basic authentication carries only once form-encoded (RFC 6749 §2.3.1).
const (
	rpRedirectURI      = "https://rp.example/callback"
	rpQueryRedirectURI = "https://rp.example/cb?tenant=a"
	rpSecret           = "s3cret: 100% & more" //nolint:gosec // G101: a test value, guarding nothing.
	otherSecret        = "other secret"        //nolint:gosec // G101: a test value, guarding nothing.
	postSecret         = "post secret"
)

// The Subjects of alice and bob in flowRegistry.
const (
	aliceSubject = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
	bobSubject   = "0b5c3c62-1f3e-4f2b-9f43-8c1d2e3f4a5b"
)

// aliceClaims are alice's claims in flowRegistry: every Standard Claim of
// OpenID Connect Core 1.0 §5.1 other than sub. bob has none.
const aliceClaims = `{
	"name": "Alice Smith", "given_name": "Alice", "family_name": "Smith", "middle_name": "Jane",
	"nickname": "Ally", "preferred_username": "alice", "profile": "https://alice.example/profile",
	"picture": "https://alice.example/me.jpg", "website": "https://alice.example",
	"email": "alice@example.com", "email_verified": true, "gender": "female",
	"birthdate": "1990-05-04", "zoneinfo": "Europe/Paris", "locale": "en-US",
	"phone_number": "+1 555 0100", "phone_number_verified": false,
	"address": {"formatted": "1 Main St, Springfield, 12345, US", "street_address": "1 Main St",
		"locality": "Springfield", "region": "IL", "postal_code": "12345", "country": "US"},
	"updated_at": 1700000000
}`

// flowRegistry returns a registry of five Clients and the End-Users alice,
// with aliceClaims, and bob: rp and other authenticate with
// client_secret_basic, post with client_secret_post, and jwt with
// private_key_jwt, by the public keys of jwtKeys; public is a public
// Client.
func flowRegistry(tb testing.TB) *registry.Registry {
	tb.Helper()
	reg, err := registry.Parse(flowRegistryFile(tb))
	if err != nil {
		tb.Fatal(err)
	}
	return reg
}

// flowRegistryWithout returns flowRegistry without the Client whose
// client_id, or the End-User whose sub, is id, as a deployment's registry
// is once one is removed from its file.
func flowRegistryWithout(tb testing.TB, id string) *registry.Registry {
	tb.Helper()
	var file map[string][]map[string]any
	if err := json.Unmarshal(flowRegistryFile(tb), &file); err != nil {
		tb.Fatal(err)
	}
	removed := 0
	for _, list := range []string{"clients", "end_users"} {
		file[list] = slices.DeleteFunc(file[list], func(e map[string]any) bool {
			if e["client_id"] == id || e["sub"] == id {
				removed++
				return true
			}
			return false
		})
	}
	if removed != 1 {
		tb.Fatalf("flowRegistry has %d entries named %q, want 1", removed, id)
	}
	b, err := json.Marshal(file)
	if err != nil {
		tb.Fatal(err)
	}
	reg, err := registry.Parse(b)
	if err != nil {
		tb.Fatal(err)
	}
	return reg
}

// flowRegistryFile returns the registry file of flowRegistry.
func flowRegistryFile(tb testing.TB) []byte {
	tb.Helper()
	return []byte(`{
		"clients": [
			{"client_id": "rp", "token_endpoint_auth_method": "client_secret_basic", "client_secret_hash": "` + hashPassword(tb, rpSecret) + `",
			 "redirect_uris": ["` + rpRedirectURI + `", "` + rpQueryRedirectURI + `"]},
			{"client_id": "other", "token_endpoint_auth_method": "client_secret_basic", "client_secret_hash": "` + hashPassword(tb, otherSecret) + `",
			 "redirect_uris": ["https://other.example/callback"]},
			{"client_id": "post", "token_endpoint_auth_method": "client_secret_post", "client_secret_hash": "` + hashPassword(tb, postSecret) + `",
			 "redirect_uris": ["` + postRedirectURI + `"]},
			{"client_id": "jwt", "token_endpoint_auth_method": "private_key_jwt", "jwks": ` + jwtJWKS(tb) + `,
			 "redirect_uris": ["` + jwtRedirectURI + `"]},
			{"client_id": "public", "token_endpoint_auth_method": "none", "redirect_uris": ["` + publicRedirectURI + `"]}
		],
		"end_users": [
			{"sub": "` + aliceSubject + `", "username": "alice", "password_hash": "` + hashPassword(tb, alicePassword) + `",
			 "claims": ` + aliceClaims + `},
			{"sub": "` + bobSubject + `", "username": "bob", "password_hash": "` + hashPassword(tb, bobPassword) + `"}
		]
	}`)
}

// newFlowHandler returns the handler of an OP at loginIssuer, with the
// Clients and End-User of flowRegistry, backed by pool, with its signing
// keys loaded.
func newFlowHandler(tb testing.TB, pool *pgxpool.Pool) http.Handler {
	tb.Helper()
	return newFlowHandlerFor(tb, pool, flowRegistry(tb))
}

// newFlowHandlerFor returns the handler of newFlowHandler with the
// registry reg, as pulsar is when started with another registry file
// against the same database.
func newFlowHandlerFor(tb testing.TB, pool *pgxpool.Pool, reg *registry.Registry) http.Handler {
	tb.Helper()
	keys := signing.New(pool, config.Secret{})
	if err := keys.Load(tb.Context()); err != nil {
		tb.Fatalf("Load() error = %v", err)
	}
	return New(slog.New(slog.NewTextHandler(tb.Output(), nil)), mustParse(tb, loginIssuer), pool, keys, reg, ready())
}

// newFlowHandlerWithoutDatabase returns the handler of newFlowHandler with
// PostgreSQL unreachable and no signing keys, for requests that must be
// answered before either is needed.
func newFlowHandlerWithoutDatabase(tb testing.TB) http.Handler {
	tb.Helper()
	pool := postgrestest.Open(tb, postgrestest.UnreachableURL(tb))
	logger := slog.New(slog.DiscardHandler)
	return New(logger, mustParse(tb, loginIssuer), pool, signing.New(pool, config.Secret{}), flowRegistry(tb), ready())
}

// newBubbleFlowHandler returns the handler of newFlowHandler for the
// database at databaseURL, for a test inside a testing/synctest bubble, so
// that the test controls the clock that dates codes and tokens. The pool
// is opened inside the bubble, and closed there as the bubble ends;
// databaseURL must name an address rather than a host name, as in
// TestLoginSessionLimits.
func newBubbleFlowHandler(t *testing.T, databaseURL string) http.Handler {
	t.Helper()
	return newFlowHandler(t, newBubblePool(t, databaseURL))
}

// newBubblePool opens a pool for the database at databaseURL inside a
// testing/synctest bubble, and closes it as the bubble ends.
func newBubblePool(t *testing.T, databaseURL string) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// deleteDue deletes the codes and tokens due at the bubble's now from the
// database behind pool, as pulsar's periodic task does (cmd/pulsar) when
// it runs then.
func deleteDue(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if err := oidc.DeleteDue(t.Context(), pool, time.Now()); err != nil {
		t.Fatalf("oidc.DeleteDue() = %v, want nil", err)
	}
}

// authorizationParams returns the parameters of a valid authorization
// request from rp.
func authorizationParams() url.Values {
	return url.Values{
		"client_id":     {"rp"},
		"redirect_uri":  {rpRedirectURI},
		"response_type": {"code"},
		"scope":         {"openid profile"},
		"state":         {"af0ifjsldkj"},
		"nonce":         {"n-0S6_WzA2Mj"},
	}
}

// send sends a request for target, a path with any query, by method; a
// POST carries form as its body.
func (b *browser) send(method, target string, form url.Values) response {
	b.t.Helper()
	var req *http.Request
	if method == http.MethodPost {
		req = httptest.NewRequestWithContext(b.t.Context(), method, "https://op.example"+target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequestWithContext(b.t.Context(), method, "https://op.example"+target, http.NoBody)
	}
	return b.do(req)
}

// authorize sends an authorization request with params, by method.
func (b *browser) authorize(method string, params url.Values) response {
	b.t.Helper()
	if method == http.MethodPost {
		return b.send(method, authorizationPath, params)
	}
	return b.send(method, authorizationPath+"?"+params.Encode(), nil)
}

// headers returns the value of each header that want names, so that a
// test compares with want only the headers it checks.
func headers(h http.Header, want map[string]string) map[string]string {
	got := make(map[string]string, len(want))
	for k := range want {
		got[k] = h.Get(k)
	}
	return got
}

// location returns the Location of a 303 response, failing the test for
// any other.
func location(t *testing.T, resp response) *url.URL {
	t.Helper()
	if resp.status != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d; body %q", resp.status, http.StatusSeeOther, resp.body)
	}
	u, err := url.Parse(resp.header.Get("Location"))
	if err != nil {
		t.Fatalf("Location %q is not a URL: %v", resp.header.Get("Location"), err)
	}
	return u
}

// withoutQuery returns u without its query.
func withoutQuery(u *url.URL) string {
	v := *u
	v.RawQuery = ""
	return v.String()
}

// signIn follows the redirect to the login page in resp, signs in there as
// alice, and returns the response to the authorization request the login
// page sends the browser back to.
func (b *browser) signIn(resp response) response {
	b.t.Helper()
	return b.signInAs(resp, "alice", alicePassword)
}

// signInAs is signIn as the End-User with username and password.
func (b *browser) signInAs(resp response, username, password string) response {
	b.t.Helper()
	loginURL := location(b.t, resp)
	if loginURL.Path != loginPath {
		b.t.Fatalf("authorization request redirected to %q, want the login page %q", loginURL, loginPath)
	}
	resp = b.send(http.MethodPost, loginURL.RequestURI(), url.Values{"username": {username}, "password": {password}})
	return b.send(http.MethodGet, location(b.t, resp).RequestURI(), nil)
}

// code signs a new browser in as alice through an authorization request
// from rp with params, allows it on the consent page if alice's Consent
// does not already cover it, and returns the code the response carries.
func code(t *testing.T, handler http.Handler, params url.Values) string {
	t.Helper()
	b := &browser{t: t, handler: handler}
	resp := b.signIn(b.authorize(http.MethodGet, params))
	if resp.status == http.StatusOK {
		resp = b.decide(resp, "allow")
	}
	u := location(t, resp)
	c := u.Query().Get("code")
	if c == "" {
		t.Fatalf("authorization response %q has no code", u)
	}
	return c
}

// tokenRequest sends a token request with form, authenticated with HTTP
// Basic as clientID with secret, each form-encoded (RFC 6749 §2.3.1), or
// unauthenticated if clientID is "".
func tokenRequest(t *testing.T, handler http.Handler, clientID, secret string, form url.Values) response {
	t.Helper()
	b := &browser{t: t, handler: handler}
	return b.do(newTokenRequest(t, clientID, secret, form))
}

// newTokenRequest returns a token request with form, from clientID with
// secret by HTTP Basic authentication, or without authentication if
// clientID is "".
func newTokenRequest(t *testing.T, clientID, secret string, form url.Values) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://op.example"+tokenPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientID != "" {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
	}
	return req
}

// codeForm returns the form of a token request that redeems code for
// rpRedirectURI.
func codeForm(code string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpRedirectURI}}
}

// jwt is a verified JWT: the members of its header that tests check, and
// its claims.
type jwt struct {
	alg, kid, typ string
	claims        map[string]any
}

// verify verifies token, signed with RS256, against the JWK Set the
// handler serves, and returns it.
func verify(t *testing.T, handler http.Handler, token string) jwt {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://op.example"+jwksPath, http.NoBody))
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatalf("GET %s body is not a JWK Set: %v", jwksPath, err)
	}
	jws, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("jose.ParseSignedCompact(%q) error = %v", token, err)
	}
	payload, err := jws.Verify(&set)
	if err != nil {
		t.Fatalf("Verify(%q) against the JWK Set error = %v", token, err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("claims of %q are not a JSON object: %v", token, err)
	}
	h := jws.Signatures[0].Header
	typ, _ := h.ExtraHeaders[jose.HeaderType].(string)
	return jwt{alg: h.Algorithm, kid: h.KeyID, typ: typ, claims: claims}
}

// REQ-CORE-2, REQ-CORE-3, REQ-CORE-4, REQ-CORE-7, REQ-CORE-10,
// REQ-CORE-11, REQ-CORE-12, REQ-CORE-13, REQ-OAUTH-3, REQ-OAUTH-4,
// REQ-OAUTH-9, REQ-OAUTH-13, REQ-OAUTH-21, REQ-ISS-2, REQ-AT-1, REQ-AT-2,
// REQ-AT-3, REQ-AT-4, REQ-AT-5, REQ-BCP-4: a Client sends an End-User
// without a Login Session to the authorization endpoint, by GET or POST;
// the End-User signs in and returns to it; the Client redeems the code
// for an ID token that verifies against the JWK Set and an access token.
// A second request from the signed-in browser skips the login page.
func TestAuthorizationCodeFlow(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
			synctest.Test(t, func(t *testing.T) {
				handler := newBubbleFlowHandler(t, databaseURL)
				start := time.Now()
				params := authorizationParams()
				params.Set("scope", "openid profile unknown")
				params.Set("x-unknown", "ignored")

				b := &browser{t: t, handler: handler}
				resp := b.authorize(method, params)
				if method == http.MethodPost {
					// A POST without the Login Session cookie is first
					// sent back by GET (TestAuthorizationPOSTWithoutLoginSessionCookie).
					resp = b.send(http.MethodGet, location(t, resp).RequestURI(), nil)
				}
				loginURL := location(t, resp)
				if diff := cmp.Diff(params, loginURL.Query()); diff != "" {
					t.Errorf("redirect to the login page carries parameters mismatch (-want +got):\n%s", diff)
				}
				resp = b.decide(b.signIn(resp), "allow")
				callback := location(t, resp)
				if got := withoutQuery(callback); got != rpRedirectURI {
					t.Fatalf("authorization response redirects to %q, want %q", got, rpRedirectURI)
				}
				if got := resp.header.Get("Cache-Control"); got != "no-store" {
					t.Errorf("authorization response Cache-Control = %q, want %q", got, "no-store")
				}
				query := callback.Query()
				code := query.Get("code")
				wantQuery := url.Values{"code": {code}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}}
				if diff := cmp.Diff(wantQuery, query); diff != "" {
					t.Errorf("authorization response parameters mismatch (-want +got):\n%s", diff)
				}
				// At least 160 bits, so that guessing a code is as unlikely
				// as RFC 6749 §10.10 recommends.
				wantAtLeast160Bits(t, "authorization response code", code)

				resp = tokenRequest(t, handler, "rp", rpSecret, codeForm(code))
				if resp.status != http.StatusOK {
					t.Fatalf("POST %s status = %d, want %d; body %q", tokenPath, resp.status, http.StatusOK, resp.body)
				}
				wantHeader := map[string]string{"Content-Type": "application/json", "Cache-Control": "no-store", "Pragma": "no-cache"}
				gotHeader := headers(resp.header, wantHeader)
				if diff := cmp.Diff(wantHeader, gotHeader); diff != "" {
					t.Errorf("POST %s headers mismatch (-want +got):\n%s", tokenPath, diff)
				}
				var tokens struct {
					AccessToken string `json:"access_token"`
					TokenType   string `json:"token_type"`
					ExpiresIn   int64  `json:"expires_in"`
					IDToken     string `json:"id_token"`
					Scope       string `json:"scope"`
				}
				if err := json.Unmarshal([]byte(resp.body), &tokens); err != nil {
					t.Fatalf("POST %s body is not a token response: %v", tokenPath, err)
				}
				type fields struct {
					TokenType string
					ExpiresIn int64
					Scope     string
				}
				wantFields := fields{TokenType: "Bearer", ExpiresIn: 600, Scope: "openid profile"}
				gotFields := fields{TokenType: tokens.TokenType, ExpiresIn: tokens.ExpiresIn, Scope: tokens.Scope}
				if diff := cmp.Diff(wantFields, gotFields); diff != "" {
					t.Errorf("POST %s token response mismatch (-want +got):\n%s", tokenPath, diff)
				}

				now := float64(start.Unix())
				exp := now + 600
				idToken := verify(t, handler, tokens.IDToken)
				if idToken.alg != "RS256" || idToken.kid == "" || idToken.typ != "JWT" {
					t.Errorf("ID token header alg, kid, typ = %q, %q, %q, want RS256, a kid, JWT", idToken.alg, idToken.kid, idToken.typ)
				}
				wantID := map[string]any{
					"iss": loginIssuer, "sub": aliceSubject, "aud": "rp",
					"exp": exp, "iat": now, "auth_time": now,
					"nonce":   "n-0S6_WzA2Mj",
					"at_hash": atHash(tokens.AccessToken),
				}
				if diff := cmp.Diff(wantID, idToken.claims); diff != "" {
					t.Errorf("ID token claims mismatch (-want +got):\n%s", diff)
				}

				accessToken := verify(t, handler, tokens.AccessToken)
				if accessToken.alg != "RS256" || accessToken.kid != idToken.kid || accessToken.typ != "at+jwt" {
					t.Errorf("access token header alg, kid, typ = %q, %q, %q, want RS256, %q, at+jwt", accessToken.alg, accessToken.kid, accessToken.typ, idToken.kid)
				}
				jti, _ := accessToken.claims["jti"].(string)
				if jti == "" {
					t.Errorf("access token jti = %v, want a non-empty string", accessToken.claims["jti"])
				}
				wantAccess := map[string]any{
					"iss": loginIssuer, "aud": loginIssuer, "sub": aliceSubject, "client_id": "rp",
					"exp": exp, "iat": now, "jti": jti, "scope": "openid profile",
				}
				if diff := cmp.Diff(wantAccess, accessToken.claims); diff != "" {
					t.Errorf("access token claims mismatch (-want +got):\n%s", diff)
				}

				// The Login Session and the Consent now answer the next
				// request at once.
				callback = location(t, b.authorize(method, params))
				if got := withoutQuery(callback); got != rpRedirectURI || callback.Query().Get("code") == "" {
					t.Errorf("second authorization request redirected to %q, want a code at %q", callback, rpRedirectURI)
				}
			})
		})
	}
}

// REQ-CORE-4, REQ-CORE-14: an authorization request a Client sends by
// POST from its own site arrives without the Login Session cookie, which
// is SameSite=Lax. It is sent back to the authorization endpoint by GET,
// once, with the same parameters, a navigation on which the browser sends
// the cookie; that request is answered as any other. So a signed-in
// End-User gets a code, with prompt=none too, and one not signed in is
// sent to log in, or with prompt=none gets login_required.
func TestAuthorizationPOSTWithoutLoginSessionCookie(t *testing.T) {
	t.Parallel()

	loginRequired := url.Values{"error": {"login_required"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}}
	tests := []struct {
		name      string
		signedIn  bool
		set       url.Values // parameters set on the request
		wantLogin bool       // whether the GET is sent to the login page
		want      url.Values // the error response; nil for a code or the login page
	}{
		{name: "signed in", signedIn: true},
		{name: "signed in, prompt=none", signedIn: true, set: url.Values{"prompt": {"none"}}},
		{name: "not signed in", wantLogin: true},
		{name: "not signed in, prompt=none", set: url.Values{"prompt": {"none"}}, want: loginRequired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := &browser{t: t, handler: newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))}
			if tt.signedIn {
				wantCode(t, b.decide(b.signIn(b.authorize(http.MethodGet, authorizationParams())), "allow"), "first request")
			}
			session := b.session

			// The cross-site POST: the browser withholds the cookie.
			b.session = nil
			params := requestWith(tt.set)
			next := location(t, b.authorize(http.MethodPost, params))
			if next.Path != authorizationPath {
				t.Fatalf("POST %s without the cookie redirected to %q, want %q", authorizationPath, next, authorizationPath)
			}
			if diff := cmp.Diff(params, next.Query()); diff != "" {
				t.Errorf("redirect to GET %s carries parameters mismatch (-want +got):\n%s", authorizationPath, diff)
			}

			b.session = session
			resp := b.send(http.MethodGet, next.RequestURI(), nil)
			switch {
			case tt.wantLogin:
				if u := location(t, resp); u.Path != loginPath {
					t.Errorf("GET %s redirected to %q, want the login page %q", authorizationPath, u, loginPath)
				}
			case tt.want != nil:
				if diff := cmp.Diff(tt.want, errorResponse(t, resp)); diff != "" {
					t.Errorf("GET %s error response mismatch (-want +got):\n%s", authorizationPath, diff)
				}
			default:
				wantCode(t, resp, "GET "+authorizationPath)
			}
		})
	}
}

// REQ-OAUTH-5, REQ-OAUTH-10, REQ-CORE-5, REQ-BCP-2, REQ-BCP-3: a request
// whose Client is missing or unknown, or whose redirect URI is missing or
// differs in any character from every one the Client registered, gets an
// error page, which may not be framed, and is never redirected.
func TestAuthorizationErrorPage(t *testing.T) {
	t.Parallel()

	handler := newFlowHandlerWithoutDatabase(t)
	tests := []struct {
		name string
		edit func(url.Values)
	}{
		{name: "no client_id", edit: func(v url.Values) { v.Del("client_id") }},
		{name: "unknown client_id", edit: func(v url.Values) { v.Set("client_id", "unknown") }},
		{name: "client_id in another case", edit: func(v url.Values) { v.Set("client_id", "RP") }},
		{name: "repeated client_id", edit: func(v url.Values) { v.Add("client_id", "rp") }},
		{name: "no redirect_uri", edit: func(v url.Values) { v.Del("redirect_uri") }},
		{name: "repeated redirect_uri", edit: func(v url.Values) { v.Add("redirect_uri", rpRedirectURI) }},
		{name: "another Client's redirect_uri", edit: func(v url.Values) { v.Set("redirect_uri", "https://other.example/callback") }},
		{name: "trailing slash", edit: func(v url.Values) { v.Set("redirect_uri", rpRedirectURI+"/") }},
		{name: "prefix", edit: func(v url.Values) { v.Set("redirect_uri", "https://rp.example/callbac") }},
		{name: "host in another case", edit: func(v url.Values) { v.Set("redirect_uri", "https://RP.example/callback") }},
		{name: "http", edit: func(v url.Values) { v.Set("redirect_uri", "http://rp.example/callback") }},
		{name: "default port", edit: func(v url.Values) { v.Set("redirect_uri", "https://rp.example:443/callback") }},
		{name: "percent-encoded", edit: func(v url.Values) { v.Set("redirect_uri", "https://rp.example/%63allback") }},
		{name: "added query", edit: func(v url.Values) { v.Set("redirect_uri", rpRedirectURI+"?x=1") }},
		{name: "fragment", edit: func(v url.Values) { v.Set("redirect_uri", rpRedirectURI+"#x") }},
		{name: "different query", edit: func(v url.Values) { v.Set("redirect_uri", "https://rp.example/cb?tenant=b") }},
	}
	for _, tt := range tests {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			t.Run(tt.name+"/"+method, func(t *testing.T) {
				t.Parallel()
				params := authorizationParams()
				tt.edit(params)
				b := &browser{t: t, handler: handler}
				resp := b.authorize(method, params)
				if resp.status != http.StatusBadRequest {
					t.Errorf("%s %s status = %d, want %d", method, authorizationPath, resp.status, http.StatusBadRequest)
				}
				if got := resp.header.Get("Location"); got != "" {
					t.Errorf("%s %s Location = %q, want none", method, authorizationPath, got)
				}
				wantHeader := map[string]string{
					"Content-Type":            "text/html; charset=utf-8",
					"Cache-Control":           "no-store",
					"X-Frame-Options":         "DENY",
					"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
				}
				gotHeader := headers(resp.header, wantHeader)
				if diff := cmp.Diff(wantHeader, gotHeader); diff != "" {
					t.Errorf("%s %s headers mismatch (-want +got):\n%s", method, authorizationPath, diff)
				}
			})
		}
	}
}

// REQ-OAUTH-5, REQ-OAUTH-9, REQ-OAUTH-17, REQ-OAUTH-18, REQ-ISS-2,
// REQ-CORE-6, REQ-CORE-8, REQ-CORE-9, REQ-PKCE-1, REQ-PKCE-2, REQ-PKCE-3,
// REQ-PKCE-7, REQ-PKCE-8: once the Client and redirect URI are valid, an
// invalid request is redirected to the redirect URI with the error, state
// and iss, before any login; the redirect URI keeps its own query. A
// public Client must send a code_challenge; any Client that sends one must
// name S256 and send it in the form RFC 7636 §4.2 gives, and one that
// names a method must send it.
func TestAuthorizationErrorRedirect(t *testing.T) {
	t.Parallel()

	handler := newFlowHandlerWithoutDatabase(t)
	tests := []struct {
		name        string
		edit        func(url.Values)
		redirectURI string // default rpRedirectURI
		want        url.Values
	}{
		{
			name: "no response_type",
			edit: func(v url.Values) { v.Del("response_type") },
			want: url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}},
		},
		{
			name: "response_type token",
			edit: func(v url.Values) { v.Set("response_type", "token") },
			want: url.Values{"error": {"unsupported_response_type"}, "state": {"af0ifjsldkj"}},
		},
		{
			name: "response_type code id_token",
			edit: func(v url.Values) { v.Set("response_type", "code id_token") },
			want: url.Values{"error": {"unsupported_response_type"}, "state": {"af0ifjsldkj"}},
		},
		{
			name: "no scope",
			edit: func(v url.Values) { v.Del("scope") },
			want: url.Values{"error": {"invalid_scope"}, "state": {"af0ifjsldkj"}},
		},
		{
			name: "scope without openid",
			edit: func(v url.Values) { v.Set("scope", "profile email") },
			want: url.Values{"error": {"invalid_scope"}, "state": {"af0ifjsldkj"}},
		},
		{
			name: "scope with openid in another case",
			edit: func(v url.Values) { v.Set("scope", "OpenID") },
			want: url.Values{"error": {"invalid_scope"}, "state": {"af0ifjsldkj"}},
		},
		{
			name: "request",
			edit: func(v url.Values) { v.Set("request", "eyJhbGciOiJub25lIn0.e30.") },
			want: url.Values{"error": {"request_not_supported"}, "state": {"af0ifjsldkj"}},
		},
		{
			name: "request_uri",
			edit: func(v url.Values) { v.Set("request_uri", "https://rp.example/request.jwt") },
			want: url.Values{"error": {"request_uri_not_supported"}, "state": {"af0ifjsldkj"}},
		},
		{
			name: "response_mode form_post",
			edit: func(v url.Values) { v.Set("response_mode", "form_post") },
			want: url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}},
		},
		{
			name: "repeated scope",
			edit: func(v url.Values) { v.Add("scope", "openid") },
			want: url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}},
		},
		{
			name: "repeated state",
			edit: func(v url.Values) { v.Add("state", "second") },
			want: url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}},
		},
		{
			name: "repeated prompt",
			edit: func(v url.Values) { v["prompt"] = []string{"login", "consent"} },
			want: url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}},
		},
		{
			name: "repeated max_age",
			edit: func(v url.Values) { v["max_age"] = []string{"60", "60"} },
			want: url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}},
		},
		{
			name: "negative max_age",
			edit: func(v url.Values) { v.Set("max_age", "-1") },
			want: url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}},
		},
		{
			name: "fractional max_age",
			edit: func(v url.Values) { v.Set("max_age", "1.5") },
			want: url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}},
		},
		{
			name: "max_age not a number",
			edit: func(v url.Values) { v.Set("max_age", "one") },
			want: url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}},
		},
		{
			name: "no state",
			edit: func(v url.Values) { v.Del("state"); v.Del("response_type") },
			want: url.Values{"error": {"invalid_request"}},
		},
		{
			name:        "redirect URI with a query",
			edit:        func(v url.Values) { v.Set("redirect_uri", rpQueryRedirectURI); v.Del("response_type") },
			redirectURI: rpQueryRedirectURI,
			want:        url.Values{"tenant": {"a"}, "error": {"invalid_request"}, "state": {"af0ifjsldkj"}},
		},
		{
			name:        "public Client without code_challenge",
			edit:        asPublic,
			redirectURI: publicRedirectURI,
			want:        url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}},
		},
		{
			name:        "public Client with code_challenge_method plain",
			edit:        func(v url.Values) { asPublic(v); withPKCE(v); v.Set("code_challenge_method", "plain") },
			redirectURI: publicRedirectURI,
			want:        url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}},
		},
		{
			name:        "public Client with code_challenge and no code_challenge_method",
			edit:        func(v url.Values) { asPublic(v); withPKCE(v); v.Del("code_challenge_method") },
			redirectURI: publicRedirectURI,
			want:        url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}},
		},
		{
			name: "code_challenge_method plain",
			edit: func(v url.Values) { withPKCE(v); v.Set("code_challenge_method", "plain") },
			want: url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}},
		},
		{
			name: "code_challenge and no code_challenge_method",
			edit: func(v url.Values) { withPKCE(v); v.Del("code_challenge_method") },
			want: url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}},
		},
		{
			name: "code_challenge_method s256 in another case",
			edit: func(v url.Values) { withPKCE(v); v.Set("code_challenge_method", "s256") },
			want: url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}},
		},
		{
			name: "code_challenge_method unknown",
			edit: func(v url.Values) { withPKCE(v); v.Set("code_challenge_method", "S512") },
			want: url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}},
		},
		{
			name: "code_challenge_method and no code_challenge",
			edit: func(v url.Values) { withPKCE(v); v.Del("code_challenge") },
			want: url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}},
		},
		{
			name: "code_challenge of 42 characters",
			edit: func(v url.Values) { withPKCE(v); v.Set("code_challenge", pkceChallenge[1:]) },
			want: url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}},
		},
		{
			name: "code_challenge of 129 characters",
			edit: func(v url.Values) { withPKCE(v); v.Set("code_challenge", strings.Repeat("a", 129)) },
			want: url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}},
		},
		{
			name: "code_challenge with a character that is not unreserved",
			edit: func(v url.Values) { withPKCE(v); v.Set("code_challenge", strings.ReplaceAll(pkceChallenge, "-", "+")) },
			want: url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}},
		},
		{
			name: "repeated code_challenge",
			edit: func(v url.Values) { withPKCE(v); v.Add("code_challenge", pkceChallenge) },
			want: url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}},
		},
	}
	for _, tt := range tests {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			t.Run(tt.name+"/"+method, func(t *testing.T) {
				t.Parallel()
				params := authorizationParams()
				tt.edit(params)
				b := &browser{t: t, handler: handler}
				u := location(t, b.authorize(method, params))
				redirectURI := tt.redirectURI
				if redirectURI == "" {
					redirectURI = rpRedirectURI
				}
				if got := u.String(); !strings.HasPrefix(got, redirectURI) {
					t.Fatalf("%s %s redirected to %q, want a URL that starts with %q", method, authorizationPath, got, redirectURI)
				}
				got := u.Query()
				if got.Get("error_description") == "" {
					t.Errorf("%s %s error response has no error_description", method, authorizationPath)
				}
				got.Del("error_description")
				want := url.Values{"iss": {loginIssuer}}
				maps.Copy(want, tt.want)
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("%s %s error response parameters mismatch (-want +got):\n%s", method, authorizationPath, diff)
				}
			})
		}
	}
}

// REQ-OAUTH-6: a parameter without a value is treated as if it had not
// been sent, so an empty request does not fail the request and an empty
// state is not returned.
func TestAuthorizationEmptyParameters(t *testing.T) {
	t.Parallel()

	params := authorizationParams()
	params.Set("request", "")
	params.Set("state", "")
	b := &browser{t: t, handler: newFlowHandlerWithoutDatabase(t)}
	u := location(t, b.authorize(http.MethodGet, params))
	if u.Path != loginPath {
		t.Fatalf("GET %s with empty request and state redirected to %q, want the login page %q", authorizationPath, u, loginPath)
	}
	want := authorizationParams()
	want.Del("state")
	if diff := cmp.Diff(want, u.Query()); diff != "" {
		t.Errorf("redirect to the login page carries parameters mismatch (-want +got):\n%s", diff)
	}
}

// REQ-OAUTH-3, REQ-OAUTH-5, REQ-OAUTH-8, REQ-OAUTH-11, REQ-OAUTH-12,
// REQ-OAUTH-13, REQ-OAUTH-14, REQ-OAUTH-15, REQ-OAUTH-16, REQ-OAUTH-19,
// REQ-OAUTH-20: a token request
// fails, in the JSON form of RFC 6749 §5.2, when the Client does not
// authenticate by its registered method, or the code is unknown, used,
// issued to another Client or for another redirect URI, or the grant type
// is neither authorization_code nor refresh_token.
func TestTokenErrors(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	tests := []struct {
		name                string
		clientID            string
		secret              string
		redeemFirst         bool // whether the code is redeemed once before the request
		edit                func(url.Values)
		wantStatus          int
		wantError           string
		wantWWWAuthenticate bool // whether WWW-Authenticate names the Basic scheme
	}{
		{name: "code issued to another Client", clientID: "other", secret: otherSecret, wantStatus: http.StatusBadRequest, wantError: "invalid_grant"},
		{
			name: "another redirect_uri", clientID: "rp", secret: rpSecret,
			edit:       func(v url.Values) { v.Set("redirect_uri", rpQueryRedirectURI) },
			wantStatus: http.StatusBadRequest, wantError: "invalid_grant",
		},
		{
			name: "unknown code", clientID: "rp", secret: rpSecret,
			edit:       func(v url.Values) { v.Set("code", "unknown") },
			wantStatus: http.StatusBadRequest, wantError: "invalid_grant",
		},
		{name: "code already redeemed", clientID: "rp", secret: rpSecret, redeemFirst: true, wantStatus: http.StatusBadRequest, wantError: "invalid_grant"},
		{
			name: "grant_type password", clientID: "rp", secret: rpSecret,
			edit:       func(v url.Values) { v.Set("grant_type", "password") },
			wantStatus: http.StatusBadRequest, wantError: "unsupported_grant_type",
		},
		{
			name: "grant_type client_credentials", clientID: "rp", secret: rpSecret,
			edit:       func(v url.Values) { v.Set("grant_type", "client_credentials") },
			wantStatus: http.StatusBadRequest, wantError: "unsupported_grant_type",
		},
		{
			name: "no grant_type", clientID: "rp", secret: rpSecret,
			edit:       func(v url.Values) { v.Del("grant_type") },
			wantStatus: http.StatusBadRequest, wantError: "invalid_request",
		},
		{
			name: "no code", clientID: "rp", secret: rpSecret,
			edit:       func(v url.Values) { v.Del("code") },
			wantStatus: http.StatusBadRequest, wantError: "invalid_request",
		},
		{
			name: "no redirect_uri", clientID: "rp", secret: rpSecret,
			edit:       func(v url.Values) { v.Del("redirect_uri") },
			wantStatus: http.StatusBadRequest, wantError: "invalid_request",
		},
		{
			name: "repeated code", clientID: "rp", secret: rpSecret,
			edit:       func(v url.Values) { v.Add("code", v.Get("code")) },
			wantStatus: http.StatusBadRequest, wantError: "invalid_request",
		},
		{
			name: "client_secret in the body as well", clientID: "rp", secret: rpSecret,
			edit:       func(v url.Values) { v.Set("client_secret", rpSecret) },
			wantStatus: http.StatusBadRequest, wantError: "invalid_request",
		},
		{
			name: "another client_id in the body", clientID: "rp", secret: rpSecret,
			edit:       func(v url.Values) { v.Set("client_id", "other") },
			wantStatus: http.StatusBadRequest, wantError: "invalid_request",
		},
		{name: "wrong secret", clientID: "rp", secret: otherSecret, wantStatus: http.StatusUnauthorized, wantError: "invalid_client", wantWWWAuthenticate: true},
		{name: "unknown Client", clientID: "unknown", secret: rpSecret, wantStatus: http.StatusUnauthorized, wantError: "invalid_client", wantWWWAuthenticate: true},
		{name: "no authentication", wantStatus: http.StatusUnauthorized, wantError: "invalid_client", wantWWWAuthenticate: true},
		{
			name: "client_secret_post Client by Basic", clientID: "post", secret: postSecret,
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client", wantWWWAuthenticate: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			form := codeForm(code(t, handler, authorizationParams()))
			if tt.redeemFirst {
				if resp := tokenRequest(t, handler, "rp", rpSecret, form); resp.status != http.StatusOK {
					t.Fatalf("first POST %s status = %d, want %d; body %q", tokenPath, resp.status, http.StatusOK, resp.body)
				}
			}
			if tt.edit != nil {
				tt.edit(form)
			}
			resp := tokenRequest(t, handler, tt.clientID, tt.secret, form)

			if resp.status != tt.wantStatus {
				t.Errorf("POST %s status = %d, want %d", tokenPath, resp.status, tt.wantStatus)
			}
			var body struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal([]byte(resp.body), &body); err != nil {
				t.Fatalf("POST %s body %q is not JSON: %v", tokenPath, resp.body, err)
			}
			if body.Error != tt.wantError {
				t.Errorf("POST %s error = %q, want %q", tokenPath, body.Error, tt.wantError)
			}
			wantHeader := map[string]string{
				"Content-Type":     "application/json",
				"Cache-Control":    "no-store",
				"Pragma":           "no-cache",
				"WWW-Authenticate": "",
			}
			if tt.wantWWWAuthenticate {
				wantHeader["WWW-Authenticate"] = `Basic realm="` + loginIssuer + `"`
			}
			gotHeader := headers(resp.header, wantHeader)
			if diff := cmp.Diff(wantHeader, gotHeader); diff != "" {
				t.Errorf("POST %s headers mismatch (-want +got):\n%s", tokenPath, diff)
			}
		})
	}
}

// REQ-OAUTH-6: the token endpoint treats a parameter without a value as if
// it had not been sent, and reads parameters from the body only, so a
// malformed query does not fail the request.
func TestTokenParameters(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	tests := []struct {
		name  string
		query string
		edit  func(url.Values)
	}{
		{name: "empty client_secret", edit: func(v url.Values) { v.Set("client_secret", "") }},
		{name: "empty repeat of code", edit: func(v url.Values) { v.Add("code", "") }},
		{name: "malformed query", query: "?%zz"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			form := codeForm(code(t, handler, authorizationParams()))
			if tt.edit != nil {
				tt.edit(form)
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://op.example"+tokenPath, strings.NewReader(form.Encode()))
			req.URL.RawQuery = strings.TrimPrefix(tt.query, "?")
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetBasicAuth("rp", url.QueryEscape(rpSecret))
			resp := (&browser{t: t, handler: handler}).do(req)
			if resp.status != http.StatusOK {
				t.Errorf("POST %s%s status = %d, want %d; body %q", tokenPath, tt.query, resp.status, http.StatusOK, resp.body)
			}
		})
	}
}

// REQ-OAUTH-3: a Client whose secret holds characters that form-encoding
// changes, and that sends it in HTTP Basic authentication without
// form-encoding it, fails to authenticate: "%" in rp's secret starts no
// valid escape.
func TestTokenBasicCredentialsFormEncoded(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	form := codeForm(code(t, handler, authorizationParams()))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://op.example"+tokenPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("rp", rpSecret)
	resp := (&browser{t: t, handler: handler}).do(req)
	if resp.status != http.StatusUnauthorized {
		t.Errorf("POST %s with the secret not form-encoded status = %d, want %d", tokenPath, resp.status, http.StatusUnauthorized)
	}
}

// REQ-OAUTH-7, REQ-OAUTH-16, REQ-OAUTH-19: a code can be redeemed for 60
// seconds after it is issued; after that, the token request fails with
// invalid_grant.
func TestTokenCodeExpiry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		wait       time.Duration
		wantStatus int
		wantError  string
	}{
		{wait: 59 * time.Second, wantStatus: http.StatusOK},
		{wait: 60 * time.Second, wantStatus: http.StatusBadRequest, wantError: "invalid_grant"},
	}
	for _, tt := range tests {
		t.Run(tt.wait.String(), func(t *testing.T) {
			t.Parallel()
			databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
			synctest.Test(t, func(t *testing.T) {
				handler := newBubbleFlowHandler(t, databaseURL)
				form := codeForm(code(t, handler, authorizationParams()))
				time.Sleep(tt.wait)
				resp := tokenRequest(t, handler, "rp", rpSecret, form)
				if resp.status != tt.wantStatus {
					t.Errorf("POST %s %v after the code was issued status = %d, want %d; body %q", tokenPath, tt.wait, resp.status, tt.wantStatus, resp.body)
				}
				var body struct {
					Error string `json:"error"`
				}
				if err := json.Unmarshal([]byte(resp.body), &body); err != nil {
					t.Fatalf("POST %s body %q is not JSON: %v", tokenPath, resp.body, err)
				}
				if body.Error != tt.wantError {
					t.Errorf("POST %s %v after the code was issued error = %q, want %q", tokenPath, tt.wait, body.Error, tt.wantError)
				}
			})
		})
	}
}

// REQ-OAUTH-10: whatever the parameters of an authorization request, by
// GET or POST, the endpoint answers with an error page, a redirect to the
// login page, a POST with a redirect to itself, or a redirect to one of
// the redirect URIs rp registered with iss; never a redirect anywhere
// else.
func FuzzAuthorizationRequest(f *testing.F) {
	f.Add(authorizationParams().Encode())
	f.Add("client_id=rp&redirect_uri=https%3A%2F%2Frp.example%2Fcallback")
	f.Add("client_id=rp&redirect_uri=https%3A%2F%2Frp.example%2Fcb%3Ftenant%3Da&request=x&state=%00")
	f.Add("client_id=rp&client_id=other&redirect_uri=https%3A%2F%2Fevil.example")
	f.Add("client_id=rp;redirect_uri=x&%zz")
	f.Add(requestWith(url.Values{"claims": {`{"id_token": {"sub": {"values": ["a", 1]}}, "userinfo": {"name": {"value": null}}}`}}).Encode())
	f.Add(requestWith(url.Values{"claims": {`{"userinfo": {"email": {"values": []}}, "userinfo": null}`}}).Encode())
	f.Add("")

	handler := newFlowHandlerWithoutDatabase(f)
	registered := []string{rpRedirectURI, rpQueryRedirectURI}
	f.Fuzz(func(t *testing.T, raw string) {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			var req *http.Request
			if method == http.MethodPost {
				req = httptest.NewRequestWithContext(t.Context(), method, "https://op.example"+authorizationPath, strings.NewReader(raw))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			} else {
				req = httptest.NewRequestWithContext(t.Context(), method, "https://op.example"+authorizationPath, http.NoBody)
				req.URL.RawQuery = raw
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			loc := rec.Header().Get("Location")
			switch rec.Code {
			case http.StatusBadRequest:
				if loc != "" {
					t.Errorf("%s %s?%q status 400 has Location %q, want none", method, authorizationPath, raw, loc)
				}
			case http.StatusSeeOther:
				if strings.HasPrefix(loc, loginPath+"?") || (method == http.MethodPost && strings.HasPrefix(loc, authorizationPath+"?")) {
					continue
				}
				if !redirectsTo(loc, registered) {
					t.Errorf("%s %s?%q redirected to %q, want the login page or a registered redirect URI", method, authorizationPath, raw, loc)
					continue
				}
				u, err := url.Parse(loc)
				if err != nil || u.Query().Get("iss") != loginIssuer {
					t.Errorf("%s %s?%q redirected to %q, want iss %q", method, authorizationPath, raw, loc, loginIssuer)
				}
			default:
				t.Errorf("%s %s?%q status = %d, want %d or %d", method, authorizationPath, raw, rec.Code, http.StatusBadRequest, http.StatusSeeOther)
			}
		}
	})
}

// redirectsTo reports whether loc is one of uris with parameters added to
// its query.
func redirectsTo(loc string, uris []string) bool {
	for _, u := range uris {
		sep := "?"
		if strings.Contains(u, "?") {
			sep = "&"
		}
		if strings.HasPrefix(loc, u+sep) {
			return true
		}
	}
	return false
}
