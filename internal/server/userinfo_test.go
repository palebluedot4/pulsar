package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palebluedot4/pulsar/internal/config"
	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
	"github.com/palebluedot4/pulsar/internal/signing"
)

// userInfoPath is the path of the UserInfo endpoint under loginIssuer.
const userInfoPath = "/tenant/userinfo"

// alice's claims as UserInfo returns them for each scope (OpenID Connect
// Core 1.0 §5.4), decoded from JSON.
var (
	aliceProfile = map[string]any{
		"name": "Alice Smith", "given_name": "Alice", "family_name": "Smith", "middle_name": "Jane",
		"nickname": "Ally", "preferred_username": "alice", "profile": "https://alice.example/profile",
		"picture": "https://alice.example/me.jpg", "website": "https://alice.example",
		"gender": "female", "birthdate": "1990-05-04", "zoneinfo": "Europe/Paris", "locale": "en-US",
		"updated_at": float64(1700000000),
	}
	aliceEmail   = map[string]any{"email": "alice@example.com", "email_verified": true}
	aliceAddress = map[string]any{"address": map[string]any{
		"formatted": "1 Main St, Springfield, 12345, US", "street_address": "1 Main St",
		"locality": "Springfield", "region": "IL", "postal_code": "12345", "country": "US",
	}}
	alicePhone = map[string]any{"phone_number": "+1 555 0100", "phone_number_verified": false}
)

// claimsOf returns alice's sub with the claims of each of sets.
func claimsOf(sets ...map[string]any) map[string]any {
	claims := map[string]any{"sub": aliceSubject}
	for _, s := range sets {
		maps.Copy(claims, s)
	}
	return claims
}

// issuedTokens signs a new browser in as alice through rp's authorization
// request with params, redeems the code, and returns the access token and
// the ID token.
func issuedTokens(t *testing.T, handler http.Handler, params url.Values) (accessToken, idToken string) {
	t.Helper()
	return tokensOf(t, tokenRequest(t, handler, "rp", rpSecret, codeForm(code(t, handler, params))))
}

// tokensOf returns the access token and the ID token of a successful token
// response, failing the test for any other.
func tokensOf(t *testing.T, resp response) (accessToken, idToken string) {
	t.Helper()
	if resp.status != http.StatusOK {
		t.Fatalf("POST %s status = %d, want %d; body %q", tokenPath, resp.status, http.StatusOK, resp.body)
	}
	var tokens struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.Unmarshal([]byte(resp.body), &tokens); err != nil {
		t.Fatalf("POST %s body is not a token response: %v", tokenPath, err)
	}
	return tokens.AccessToken, tokens.IDToken
}

// tokenSending is how a UserInfo request sends its access token (RFC 6750
// §2).
type tokenSending struct {
	name   string
	method string
	header bool // in the Authorization header, by the Bearer scheme
	body   bool // in the form-encoded body, as access_token
}

// The ways a Client may send a UserInfo request.
var (
	getHeader  = tokenSending{name: "GET, header", method: http.MethodGet, header: true}
	postHeader = tokenSending{name: "POST, header", method: http.MethodPost, header: true}
	postBody   = tokenSending{name: "POST, body", method: http.MethodPost, body: true}
)

// userInfo sends a UserInfo request with token, as s says.
func userInfo(t *testing.T, handler http.Handler, s tokenSending, token string) response {
	t.Helper()
	b := &browser{t: t, handler: handler}
	return b.do(newUserInfoRequest(t, s, token))
}

// newUserInfoRequest returns a UserInfo request with token, as s says.
func newUserInfoRequest(t *testing.T, s tokenSending, token string) *http.Request {
	t.Helper()
	var body io.Reader = http.NoBody
	if s.body {
		body = strings.NewReader(url.Values{"access_token": {token}}.Encode())
	}
	req := httptest.NewRequestWithContext(t.Context(), s.method, "https://op.example"+userInfoPath, body)
	if s.body {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if s.header {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

// userInfoClaims returns the claims of a successful UserInfo response,
// failing the test for any other.
func userInfoClaims(t *testing.T, resp response) map[string]any {
	t.Helper()
	if resp.status != http.StatusOK {
		t.Fatalf("UserInfo status = %d, want %d; WWW-Authenticate %q", resp.status, http.StatusOK, resp.header.Get("WWW-Authenticate"))
	}
	wantHeader := map[string]string{"Content-Type": "application/json", "Cache-Control": "no-store", "Pragma": "no-cache"}
	if diff := cmp.Diff(wantHeader, headers(resp.header, wantHeader)); diff != "" {
		t.Errorf("UserInfo headers mismatch (-want +got):\n%s", diff)
	}
	var claims map[string]any
	if err := json.Unmarshal([]byte(resp.body), &claims); err != nil {
		t.Fatalf("UserInfo body %q is not a JSON object: %v", resp.body, err)
	}
	return claims
}

// REQ-CORE-36, REQ-CORE-37, REQ-CORE-38, REQ-CORE-39, REQ-CORE-40,
// REQ-CORE-49, REQ-BEARER-1, REQ-BEARER-2: UserInfo returns, by GET or
// POST, with the access token in the Authorization header or the body,
// alice's sub and exactly the claims of the scopes granted, as JSON that
// no cache may keep.
func TestUserInfo(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	scopes := []struct {
		scope string
		want  map[string]any
	}{
		{scope: "openid", want: claimsOf()},
		{scope: "openid profile", want: claimsOf(aliceProfile)},
		{scope: "openid email", want: claimsOf(aliceEmail)},
		{scope: "openid address", want: claimsOf(aliceAddress)},
		{scope: "openid phone", want: claimsOf(alicePhone)},
		{scope: "openid profile email address phone", want: claimsOf(aliceProfile, aliceEmail, aliceAddress, alicePhone)},
	}
	for _, s := range []tokenSending{getHeader, postHeader, postBody} {
		for _, sc := range scopes {
			t.Run(s.name+"/"+sc.scope, func(t *testing.T) {
				t.Parallel()
				accessToken, _ := issuedTokens(t, handler, withScope(sc.scope))
				got := userInfoClaims(t, userInfo(t, handler, s, accessToken))
				if diff := cmp.Diff(sc.want, got); diff != "" {
					t.Errorf("UserInfo %s with scope %q claims mismatch (-want +got):\n%s", s.name, sc.scope, diff)
				}
			})
		}
	}
}

// bearerChallenge is the WWW-Authenticate challenge of a UserInfo error
// response without an error code (RFC 6750 §3).
const bearerChallenge = `Bearer realm="` + loginIssuer + `"`

// bearerErrorCode matches the error attribute of a Bearer challenge.
var bearerErrorCode = regexp.MustCompile(`, error="([^"]*)"`)

// userInfoError returns the error code in the WWW-Authenticate challenge
// of a UserInfo error response, or "" if it has none, failing the test
// unless the response has status and a Bearer challenge for loginIssuer
// that no cache may keep.
func userInfoError(t *testing.T, resp response, status int) string {
	t.Helper()
	if resp.status != status {
		t.Errorf("UserInfo status = %d, want %d; body %q", resp.status, status, resp.body)
	}
	if got := resp.header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("UserInfo Cache-Control = %q, want %q", got, "no-store")
	}
	challenge := resp.header.Get("WWW-Authenticate")
	if !strings.HasPrefix(challenge, bearerChallenge) {
		t.Fatalf("UserInfo WWW-Authenticate = %q, want a challenge that starts %q", challenge, bearerChallenge)
	}
	m := bearerErrorCode.FindStringSubmatch(challenge)
	if m == nil {
		if challenge != bearerChallenge {
			t.Errorf("UserInfo WWW-Authenticate = %q, want %q or one with an error", challenge, bearerChallenge)
		}
		return ""
	}
	return m[1]
}

// forger signs JWTs with the OP's own signing key, read from the database
// the handler uses, so that a test can present a token the OP's key
// signed with any header typ and claims.
func forger(t *testing.T, pool *pgxpool.Pool) *signing.KeySet {
	t.Helper()
	keys := signing.New(pool, config.Secret{})
	if err := keys.Load(t.Context()); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	return keys
}

// forge returns a JWT signed with keys, with typ and claims.
func forge(t *testing.T, keys *signing.KeySet, typ string, claims map[string]any) string {
	t.Helper()
	token, err := keys.SignJWT(typ, claims)
	if err != nil {
		t.Fatalf("SignJWT() error = %v", err)
	}
	return token
}

// REQ-AT-6, REQ-AT-7, REQ-AT-8, REQ-AT-9, REQ-AT-10, REQ-AT-11,
// REQ-BEARER-4, REQ-BEARER-5, REQ-CORE-41: an access token that the OP's
// key did not sign by RS256, or whose typ is not at+jwt, whose iss is not
// the issuer, whose aud does not hold the issuer, or that has expired, or
// that has no current record, is refused with 401 and invalid_token. A
// token that passes every check, however it was made, is accepted.
func TestUserInfoInvalidToken(t *testing.T) {
	t.Parallel()

	pool := postgrestest.Open(t, postgrestest.NewDatabase(t))
	handler := newFlowHandler(t, pool)
	keys := forger(t, pool)
	accessToken, idToken := issuedTokens(t, handler, withScope("openid email"))
	valid := verify(t, handler, accessToken).claims
	with := func(name string, value any) map[string]any {
		c := maps.Clone(valid)
		if value == nil {
			delete(c, name)
		} else {
			c[name] = value
		}
		return c
	}
	other := jwtKey(jose.RS256)
	// The issued token with its claims widened to every scope and its
	// signature kept.
	parts := strings.Split(accessToken, ".")
	widened, err := json.Marshal(with("scope", "openid profile email address phone"))
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(widened) + "." + parts[2]
	tests := []struct {
		name  string
		token string
		ok    bool // the token passes every check
	}{
		{name: "issued", token: accessToken, ok: true},
		{name: "forged with every claim valid", token: forge(t, keys, "at+jwt", valid), ok: true},
		{name: "typ with the application/ prefix", token: forge(t, keys, "application/at+jwt", valid), ok: true},
		{name: "aud an array holding the issuer", token: forge(t, keys, "at+jwt", with("aud", []string{"https://rs.example", loginIssuer})), ok: true},
		{name: "claims changed after signing", token: tampered},
		{name: "signed by another key", token: signAssertion(t, other.alg, other.key, valid["jti"].(string)[:4], valid)},
		{name: "unsigned, alg none", token: unsigned(t, valid)},
		{name: "not a JWT", token: "mF_9.B5f-4.1JqM"}, //nolint:gosec // G101: RFC 6750's example token, guarding nothing.
		{name: "the ID token", token: idToken},
		{name: "typ JWT", token: forge(t, keys, "JWT", valid)},
		{name: "another iss", token: forge(t, keys, "at+jwt", with("iss", "https://op.example"))},
		{name: "another aud", token: forge(t, keys, "at+jwt", with("aud", "https://rs.example"))},
		{name: "aud the Client", token: forge(t, keys, "at+jwt", with("aud", "rp"))},
		{name: "no aud", token: forge(t, keys, "at+jwt", with("aud", nil))},
		{name: "expired", token: forge(t, keys, "at+jwt", with("exp", time.Now().Add(-time.Second).Unix()))},
		{name: "no exp", token: forge(t, keys, "at+jwt", with("exp", nil))},
		{name: "jti with no record", token: forge(t, keys, "at+jwt", with("jti", rand.Text()))},
		{name: "sub of no End-User", token: forge(t, keys, "at+jwt", with("sub", "00000000-0000-4000-8000-000000000000"))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp := userInfo(t, handler, getHeader, tt.token)
			if tt.ok {
				if diff := cmp.Diff(claimsOf(aliceEmail), userInfoClaims(t, resp)); diff != "" {
					t.Errorf("UserInfo claims mismatch (-want +got):\n%s", diff)
				}
				return
			}
			if got := userInfoError(t, resp, http.StatusUnauthorized); got != "invalid_token" {
				t.Errorf("UserInfo error = %q, want %q", got, "invalid_token")
			}
		})
	}
}

// REQ-AT-10, REQ-AT-11, REQ-BEARER-5: an access token is accepted until
// its exp, ten minutes after it was issued, and refused with invalid_token
// from then on.
func TestUserInfoTokenExpires(t *testing.T) {
	t.Parallel()

	databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
	synctest.Test(t, func(t *testing.T) {
		handler := newBubbleFlowHandler(t, databaseURL)
		accessToken, _ := issuedTokens(t, handler, withScope("openid"))
		time.Sleep(10*time.Minute - time.Second)
		if diff := cmp.Diff(claimsOf(), userInfoClaims(t, userInfo(t, handler, getHeader, accessToken))); diff != "" {
			t.Errorf("UserInfo a second before exp claims mismatch (-want +got):\n%s", diff)
		}
		time.Sleep(time.Second)
		if got := userInfoError(t, userInfo(t, handler, getHeader, accessToken), http.StatusUnauthorized); got != "invalid_token" {
			t.Errorf("UserInfo at exp error = %q, want %q", got, "invalid_token")
		}
	})
}

// REQ-BEARER-3, REQ-BEARER-4, REQ-BEARER-6, REQ-CORE-41: a request that
// sends no access token, or credentials by another scheme, gets 401 with a
// challenge and no error code; one that sends a token by two methods, or
// twice, or a Bearer header without one, gets 400 with invalid_request. A
// token in the query is not read.
func TestUserInfoRequestErrors(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	accessToken, _ := issuedTokens(t, handler, withScope("openid"))
	form := func(v url.Values) io.Reader { return strings.NewReader(v.Encode()) }
	tests := []struct {
		name       string
		method     string
		target     string // the path and query
		header     http.Header
		body       io.Reader // form-encoded, if not nil
		wantStatus int
		wantError  string
	}{
		{name: "no token", method: http.MethodGet, wantStatus: http.StatusUnauthorized},
		{name: "no token, by POST", method: http.MethodPost, body: form(url.Values{}), wantStatus: http.StatusUnauthorized},
		{
			name: "Basic credentials", method: http.MethodGet,
			header:     http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("rp:"+rpSecret))}},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "token in the query", method: http.MethodGet, target: "?" + url.Values{"access_token": {accessToken}}.Encode(),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "token in the header and the body", method: http.MethodPost,
			header:     http.Header{"Authorization": {"Bearer " + accessToken}},
			body:       form(url.Values{"access_token": {accessToken}}),
			wantStatus: http.StatusBadRequest, wantError: "invalid_request",
		},
		{
			name: "two Authorization headers", method: http.MethodGet,
			header:     http.Header{"Authorization": {"Bearer " + accessToken, "Bearer " + accessToken}},
			wantStatus: http.StatusBadRequest, wantError: "invalid_request",
		},
		{
			name: "access_token repeated in the body", method: http.MethodPost,
			body:       form(url.Values{"access_token": {accessToken, accessToken}}),
			wantStatus: http.StatusBadRequest, wantError: "invalid_request",
		},
		{
			name: "Bearer without a token", method: http.MethodGet,
			header:     http.Header{"Authorization": {"Bearer"}},
			wantStatus: http.StatusBadRequest, wantError: "invalid_request",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body := tt.body
			if body == nil {
				body = http.NoBody
			}
			req := httptest.NewRequestWithContext(t.Context(), tt.method, "https://op.example"+userInfoPath+tt.target, body)
			if tt.body != nil {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			maps.Copy(req.Header, tt.header)
			b := &browser{t: t, handler: handler}
			if got := userInfoError(t, b.do(req), tt.wantStatus); got != tt.wantError {
				t.Errorf("UserInfo error = %q, want %q", got, tt.wantError)
			}
		})
	}
}

// REQ-BEARER-1: the Bearer scheme is matched without regard to case, and
// a POST whose token is in its header may have a body of any type, or a
// form body that cannot be read.
func TestUserInfoHeaderForms(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	accessToken, _ := issuedTokens(t, handler, withScope("openid"))
	tests := []struct {
		name        string
		method      string
		auth        string
		contentType string
		body        string
	}{
		{name: "lowercase scheme", method: http.MethodGet, auth: "bearer " + accessToken},
		{name: "POST, JSON body", method: http.MethodPost, auth: "Bearer " + accessToken, contentType: "application/json", body: "{}"},
		{name: "POST, malformed form body", method: http.MethodPost, auth: "Bearer " + accessToken, contentType: "application/x-www-form-urlencoded", body: "%zz"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequestWithContext(t.Context(), tt.method, "https://op.example"+userInfoPath, strings.NewReader(tt.body))
			req.Header.Set("Authorization", tt.auth)
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			b := &browser{t: t, handler: handler}
			if diff := cmp.Diff(claimsOf(), userInfoClaims(t, b.do(req))); diff != "" {
				t.Errorf("UserInfo claims mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// REQ-CORE-41: a UserInfo request that fails for a reason of the OP's own,
// here its database gone, gets 500 without a Bearer challenge, since the
// access token is not at fault.
func TestUserInfoServerError(t *testing.T) {
	t.Parallel()

	pool := postgrestest.Open(t, postgrestest.NewDatabase(t))
	handler := newFlowHandler(t, pool)
	accessToken, _ := issuedTokens(t, handler, withScope("openid"))
	pool.Close()
	resp := userInfo(t, handler, getHeader, accessToken)
	want := map[string]string{"Cache-Control": "no-store", "WWW-Authenticate": ""}
	if resp.status != http.StatusInternalServerError {
		t.Errorf("UserInfo with the database closed status = %d, want %d", resp.status, http.StatusInternalServerError)
	}
	if diff := cmp.Diff(want, headers(resp.header, want)); diff != "" {
		t.Errorf("UserInfo with the database closed headers mismatch (-want +got):\n%s", diff)
	}
}
