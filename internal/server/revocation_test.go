package server

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"

	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
)

// revocationPath is the path of the revocation endpoint under loginIssuer.
const revocationPath = "/tenant/revoke"

// newRevocationRequest returns a revocation request with form, from
// clientID with secret by HTTP Basic authentication, or without an
// Authorization header if clientID is "".
func newRevocationRequest(t *testing.T, clientID, secret string, form url.Values) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://op.example"+revocationPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientID != "" {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
	}
	return req
}

// revocationForm returns the form of a revocation request for token, with
// hint as its token_type_hint unless it is "".
func revocationForm(token, hint string) url.Values {
	form := url.Values{"token": {token}}
	if hint != "" {
		form.Set("token_type_hint", hint)
	}
	return form
}

// revocationRequest returns a revocation request from the Client for
// token, with hint as its token_type_hint unless it is "".
func (c pkceClient) revocationRequest(t *testing.T, token, hint string) *http.Request {
	t.Helper()
	form := revocationForm(token, hint)
	if c.basic.id == "" {
		form.Set("client_id", c.clientID)
	}
	return newRevocationRequest(t, c.basic.id, c.basic.secret, form)
}

// revoke sends the Client's revocationRequest.
func (c pkceClient) revoke(t *testing.T, handler http.Handler, token, hint string) response {
	t.Helper()
	b := &browser{t: t, handler: handler}
	return b.do(c.revocationRequest(t, token, hint))
}

// wantRevocationOK fails the test unless resp is a successful revocation
// response: 200 with an empty body, which no cache may keep.
func wantRevocationOK(t *testing.T, resp response) {
	t.Helper()
	if resp.status != http.StatusOK {
		t.Fatalf("POST %s status = %d, want %d; body %q", revocationPath, resp.status, http.StatusOK, resp.body)
	}
	if resp.body != "" {
		t.Errorf("POST %s body = %q, want none", revocationPath, resp.body)
	}
	wantHeader := map[string]string{"Cache-Control": "no-store", "Pragma": "no-cache"}
	if diff := cmp.Diff(wantHeader, headers(resp.header, wantHeader)); diff != "" {
		t.Errorf("POST %s headers mismatch (-want +got):\n%s", revocationPath, diff)
	}
}

// revocationErrorCode returns the error code of a revocation error
// response, failing the test unless it has status and the form of RFC 6749
// §5.2.
func revocationErrorCode(t *testing.T, resp response, status int) string {
	t.Helper()
	return jsonErrorCode(t, revocationPath, resp, status)
}

// REQ-REVOKE-1, REQ-REVOKE-2, REQ-REVOKE-5, REQ-REVOKE-6, REQ-REVOKE-8,
// REQ-REVOKE-9, REQ-REVOKE-10, REQ-REVOKE-11, REQ-REVOKE-14: a
// confidential or a public Client revokes one of its refresh tokens, the
// newest or one already redeemed, with any token_type_hint, a wrong or an
// unknown one included, and gets 200 with an empty body. The whole Refresh
// Token Family is revoked: its newest refresh token is refused, and
// UserInfo refuses every access token issued in it.
func TestRevokeRefreshToken(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	tests := []struct {
		name     string
		client   pkceClient
		verifier string
		revoked  int // which refresh token is revoked: 0 for the code's, 1 for the newest
		hint     string
	}{
		{name: "confidential Client, newest, no hint", client: rpNoPKCE, revoked: 1},
		{name: "confidential Client, newest, hint refresh_token", client: rpNoPKCE, revoked: 1, hint: "refresh_token"},
		{name: "confidential Client, newest, hint access_token", client: rpNoPKCE, revoked: 1, hint: "access_token"},
		{name: "confidential Client, newest, unknown hint", client: rpNoPKCE, revoked: 1, hint: "id_token"},
		{name: "confidential Client, already redeemed", client: rpNoPKCE, revoked: 0},
		{name: "public Client, newest", client: publicPKCE, verifier: pkceVerifier, revoked: 1},
		{name: "public Client, hint access_token", client: publicPKCE, verifier: pkceVerifier, revoked: 1, hint: "access_token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			first := tt.client.offlineTokens(t, handler, tt.verifier, nil)
			second := tokenResponseOf(t, tt.client.refresh(t, handler, first.RefreshToken, ""))
			refreshTokens := []string{first.RefreshToken, second.RefreshToken}
			accessTokens := []string{first.AccessToken, second.AccessToken}
			wantAccepted(t, handler, "before the revocation", claimsOf(), accessTokens)

			wantRevocationOK(t, tt.client.revoke(t, handler, refreshTokens[tt.revoked], tt.hint))
			tt.client.wantRevoked(t, handler, second.RefreshToken, accessTokens)
		})
	}
}

// REQ-REVOKE-1, REQ-REVOKE-5, REQ-REVOKE-8, REQ-REVOKE-9, REQ-REVOKE-10:
// a confidential or a public Client revokes one of its
// access tokens, with any token_type_hint, a wrong one included, and gets
// 200. UserInfo refuses that token from then on, and nothing else is
// revoked: UserInfo accepts the family's other access token, and the
// family's refresh token is still redeemed.
func TestRevokeAccessToken(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	tests := []struct {
		name     string
		client   pkceClient
		verifier string
		hint     string
	}{
		{name: "confidential Client, no hint", client: rpNoPKCE},
		{name: "confidential Client, hint access_token", client: rpNoPKCE, hint: "access_token"},
		{name: "confidential Client, hint refresh_token", client: rpNoPKCE, hint: "refresh_token"},
		{name: "public Client, hint access_token", client: publicPKCE, verifier: pkceVerifier, hint: "access_token"},
		{name: "public Client, hint refresh_token", client: publicPKCE, verifier: pkceVerifier, hint: "refresh_token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			first := tt.client.offlineTokens(t, handler, tt.verifier, nil)
			second := tokenResponseOf(t, tt.client.refresh(t, handler, first.RefreshToken, ""))

			wantRevocationOK(t, tt.client.revoke(t, handler, first.AccessToken, tt.hint))
			if got := userInfoError(t, userInfo(t, handler, getHeader, first.AccessToken), http.StatusUnauthorized); got != "invalid_token" {
				t.Errorf("UserInfo with the revoked access token error = %q, want %q", got, "invalid_token")
			}
			wantAccepted(t, handler, "after another is revoked", claimsOf(), []string{second.AccessToken})
			tokenResponseOf(t, tt.client.refresh(t, handler, second.RefreshToken, ""))
		})
	}
}

// REQ-REVOKE-5, REQ-REVOKE-10: a token pulsar does not know, an ID token,
// and a refresh token or access token already revoked each get 200 with an
// empty body, whatever the token_type_hint, so that a Client retrying a
// revocation whose response it lost succeeds.
func TestRevokeInvalidToken(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	tests := []struct {
		name string
		// token returns the token revoked, given tokens issued to rp with
		// offline access, after revoking whatever it needs to first.
		token func(t *testing.T, tokens tokenResponse) string
	}{
		{name: "unknown", token: func(*testing.T, tokenResponse) string { return "unknown" }},
		{name: "ID token", token: func(_ *testing.T, tokens tokenResponse) string { return tokens.IDToken }},
		{
			name: "refresh token already revoked",
			token: func(t *testing.T, tokens tokenResponse) string {
				t.Helper()
				wantRevocationOK(t, rpNoPKCE.revoke(t, handler, tokens.RefreshToken, ""))
				return tokens.RefreshToken
			},
		},
		{
			name: "access token already revoked",
			token: func(t *testing.T, tokens tokenResponse) string {
				t.Helper()
				wantRevocationOK(t, rpNoPKCE.revoke(t, handler, tokens.AccessToken, ""))
				return tokens.AccessToken
			},
		},
		{
			name: "access token revoked with its family",
			token: func(t *testing.T, tokens tokenResponse) string {
				t.Helper()
				wantRevocationOK(t, rpNoPKCE.revoke(t, handler, tokens.RefreshToken, ""))
				return tokens.AccessToken
			},
		},
	}
	for _, tt := range tests {
		for _, hint := range []string{"", "refresh_token", "access_token"} {
			t.Run(tt.name+"/hint "+hint, func(t *testing.T) {
				t.Parallel()
				token := tt.token(t, rpNoPKCE.offlineTokens(t, handler, "", nil))
				wantRevocationOK(t, rpNoPKCE.revoke(t, handler, token, hint))
			})
		}
	}
}

// REQ-REVOKE-10: an access token that has expired, and a refresh token
// whose Refresh Token Family has ended, before and after the family is
// deleted, each get 200.
func TestRevokeExpiredToken(t *testing.T) {
	t.Parallel()

	databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
	synctest.Test(t, func(t *testing.T) {
		pool := newBubblePool(t, databaseURL)
		handler := newFlowHandler(t, pool)
		tokens := rpNoPKCE.offlineTokens(t, handler, "", nil)

		time.Sleep(10 * time.Minute)
		wantRevocationOK(t, rpNoPKCE.revoke(t, handler, tokens.AccessToken, ""))

		time.Sleep(30 * 24 * time.Hour)
		wantRevocationOK(t, rpNoPKCE.revoke(t, handler, tokens.RefreshToken, ""))
		deleteDue(t, pool)
		wantRevocationOK(t, rpNoPKCE.revoke(t, handler, tokens.RefreshToken, ""))
	})
}

// revocationAuth is how a revocation request authenticates its Client: the
// credentials it sends by HTTP Basic authentication, if any, and the
// parameters its form adds.
type revocationAuth struct {
	basic credentials
	form  func(t *testing.T) url.Values
}

// send sends a revocation request for token, authenticated as a says.
func (a revocationAuth) send(t *testing.T, handler http.Handler, token string) response {
	t.Helper()
	form := revocationForm(token, "")
	if a.form != nil {
		maps.Copy(form, a.form(t))
	}
	b := &browser{t: t, handler: handler}
	return b.do(newRevocationRequest(t, a.basic.id, a.basic.secret, form))
}

// formAuth returns a revocationAuth that adds params to the form.
func formAuth(params url.Values) revocationAuth {
	return revocationAuth{form: func(*testing.T) url.Values { return params }}
}

// assertionAuth returns a revocationAuth that authenticates jwt by a new
// client assertion.
func assertionAuth() revocationAuth {
	return revocationAuth{form: func(t *testing.T) url.Values {
		t.Helper()
		k := jwtKey(jose.RS256)
		return url.Values{"client_assertion_type": {jwtBearer}, "client_assertion": {signAssertion(t, k.alg, k.key, k.kid, assertionClaims())}}
	}}
}

// REQ-REVOKE-7, REQ-REVOKE-12, REQ-REVOKE-14, REQ-OAUTH-15: a refresh
// token or an access token presented by a Client other than the one it was
// issued to, whichever way that Client authenticates, is refused with 400
// and invalid_request, and nothing is revoked: the owner's refresh token
// is still redeemed, and UserInfo still accepts its access token.
func TestRevokeOtherClientsToken(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	tests := []struct {
		name     string
		owner    pkceClient
		verifier string
		auth     revocationAuth // the other Client's
	}{
		{name: "by client_secret_basic", owner: publicPKCE, verifier: pkceVerifier, auth: revocationAuth{basic: credentials{"rp", rpSecret}}},
		{name: "by client_secret_basic, another confidential Client", owner: rpNoPKCE, auth: revocationAuth{basic: credentials{"other", otherSecret}}},
		{name: "by client_secret_post", owner: rpNoPKCE, auth: formAuth(url.Values{"client_id": {"post"}, "client_secret": {postSecret}})},
		{name: "by private_key_jwt", owner: rpNoPKCE, auth: assertionAuth()},
		{name: "as a public Client", owner: rpNoPKCE, auth: formAuth(url.Values{"client_id": {"public"}})},
	}
	for _, tt := range tests {
		for _, kind := range []string{"refresh_token", "access_token"} {
			t.Run(tt.name+"/"+kind, func(t *testing.T) {
				t.Parallel()
				tokens := tt.owner.offlineTokens(t, handler, tt.verifier, nil)
				token := tokens.RefreshToken
				if kind == "access_token" {
					token = tokens.AccessToken
				}
				resp := tt.auth.send(t, handler, token)
				if got := revocationErrorCode(t, resp, http.StatusBadRequest); got != "invalid_request" {
					t.Errorf("POST %s with another Client's %s error = %q, want %q", revocationPath, kind, got, "invalid_request")
				}
				wantAccepted(t, handler, "after another Client's revocation", claimsOf(), []string{tokens.AccessToken})
				tokenResponseOf(t, tt.owner.refresh(t, handler, tokens.RefreshToken, ""))
			})
		}
	}
}

// accessTokenOf returns an access token issued to the Client of
// flowRegistry whose client_id is clientID, from a code it redeems by its
// registered method.
func accessTokenOf(t *testing.T, handler http.Handler, clientID string) string {
	t.Helper()
	var resp response
	switch clientID {
	case "rp":
		resp = tokenRequest(t, handler, "rp", rpSecret, codeForm(code(t, handler, authorizationParams())))
	case "post":
		resp = postTokenRequest(t, handler, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code(t, handler, clientParams("post", postRedirectURI))},
			"redirect_uri":  {postRedirectURI},
			"client_id":     {"post"},
			"client_secret": {postSecret},
		})
	case "jwt":
		k := jwtKey(jose.RS256)
		resp = postTokenRequest(t, handler, jwtForm(code(t, handler, clientParams("jwt", jwtRedirectURI)), signAssertion(t, k.alg, k.key, k.kid, assertionClaims())))
	case "public":
		resp = publicPKCE.redeem(t, handler, publicPKCE.form(publicPKCE.code(t, handler), pkceVerifier))
	default:
		t.Fatalf("accessTokenOf(%q): no such Client", clientID)
	}
	accessToken, _ := tokensOf(t, resp)
	return accessToken
}

// REQ-REVOKE-6, REQ-REVOKE-12, REQ-OAUTH-3, REQ-OAUTH-25, REQ-JWTAUTH-1,
// REQ-OAUTH-27: each Client revokes its access token by its registered
// method: client_secret_basic, client_secret_post, private_key_jwt, or,
// for a public Client, its client_id alone.
func TestRevocationClientAuthentication(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	tests := []struct {
		clientID string
		auth     revocationAuth
	}{
		{clientID: "rp", auth: revocationAuth{basic: credentials{"rp", rpSecret}}},
		{clientID: "post", auth: formAuth(url.Values{"client_id": {"post"}, "client_secret": {postSecret}})},
		{clientID: "jwt", auth: assertionAuth()},
		{clientID: "public", auth: formAuth(url.Values{"client_id": {"public"}})},
	}
	for _, tt := range tests {
		t.Run(tt.clientID, func(t *testing.T) {
			t.Parallel()
			accessToken := accessTokenOf(t, handler, tt.clientID)
			wantRevocationOK(t, tt.auth.send(t, handler, accessToken))
			if got := userInfoError(t, userInfo(t, handler, getHeader, accessToken), http.StatusUnauthorized); got != "invalid_token" {
				t.Errorf("UserInfo with %s's revoked access token error = %q, want %q", tt.clientID, got, "invalid_token")
			}
		})
	}
}

// REQ-REVOKE-6, REQ-REVOKE-12, REQ-REVOKE-14, REQ-OAUTH-14, REQ-OAUTH-24,
// REQ-OAUTH-26, REQ-OAUTH-27, REQ-ASSERT-2: a revocation request whose
// Client fails to authenticate by its registered method fails with
// invalid_client, or invalid_request for two methods at once, and revokes
// nothing: UserInfo still accepts the token.
func TestRevocationClientAuthenticationFails(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	tests := []struct {
		name       string
		owner      string // the Client the token is issued to
		auth       revocationAuth
		wantStatus int
		wantError  string
	}{
		{name: "wrong secret", owner: "rp", auth: revocationAuth{basic: credentials{"rp", otherSecret}}, wantStatus: http.StatusUnauthorized, wantError: "invalid_client"},
		{name: "unknown Client", owner: "rp", auth: revocationAuth{basic: credentials{"unknown", rpSecret}}, wantStatus: http.StatusUnauthorized, wantError: "invalid_client"},
		{name: "no credentials", owner: "rp", wantStatus: http.StatusUnauthorized, wantError: "invalid_client"},
		{name: "confidential Client by client_id alone", owner: "rp", auth: formAuth(url.Values{"client_id": {"rp"}}), wantStatus: http.StatusUnauthorized, wantError: "invalid_client"},
		{
			name: "client_secret_basic Client by the body", owner: "rp",
			auth:       formAuth(url.Values{"client_id": {"rp"}, "client_secret": {rpSecret}}),
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		{
			name: "client_secret_post Client by Basic", owner: "post",
			auth:       revocationAuth{basic: credentials{"post", postSecret}},
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		{
			name: "private_key_jwt Client by the body", owner: "jwt",
			auth:       formAuth(url.Values{"client_id": {"jwt"}, "client_secret": {postSecret}}),
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		{
			name: "invalid assertion", owner: "jwt",
			auth:       formAuth(url.Values{"client_assertion_type": {jwtBearer}, "client_assertion": {"not-a-jwt"}}),
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		{name: "public Client without client_id", owner: "public", wantStatus: http.StatusUnauthorized, wantError: "invalid_client"},
		{
			name: "Basic and the body", owner: "post",
			auth: revocationAuth{
				basic: credentials{"post", postSecret},
				form:  func(*testing.T) url.Values { return url.Values{"client_id": {"post"}, "client_secret": {postSecret}} },
			},
			wantStatus: http.StatusBadRequest, wantError: "invalid_request",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			accessToken := accessTokenOf(t, handler, tt.owner)
			if got := revocationErrorCode(t, tt.auth.send(t, handler, accessToken), tt.wantStatus); got != tt.wantError {
				t.Errorf("POST %s error = %q, want %q", revocationPath, got, tt.wantError)
			}
			wantAccepted(t, handler, "after a revocation that failed", claimsOf(aliceProfile), []string{accessToken})
		})
	}
}

// REQ-REVOKE-17, REQ-OAUTH-44: failed attempts to authenticate as a Client
// at the revocation endpoint are not counted against it, as at the token
// endpoint, so that no one who knows its client_id can hold up its
// revocations: after many with a wrong secret, by either method, it still
// authenticates with its own.
func TestRevocationClientSecretNotThrottled(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	tests := []struct {
		clientID     string
		wrong, right revocationAuth
	}{
		{
			clientID: "rp",
			wrong:    revocationAuth{basic: credentials{"rp", "wrong"}},
			right:    revocationAuth{basic: credentials{"rp", rpSecret}},
		},
		{
			clientID: "post",
			wrong:    formAuth(url.Values{"client_id": {"post"}, "client_secret": {"wrong"}}),
			right:    formAuth(url.Values{"client_id": {"post"}, "client_secret": {postSecret}}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.clientID, func(t *testing.T) {
			t.Parallel()
			accessToken := accessTokenOf(t, handler, tt.clientID)
			for i := range 20 {
				if got := revocationErrorCode(t, tt.wrong.send(t, handler, accessToken), http.StatusUnauthorized); got != "invalid_client" {
					t.Fatalf("POST %s with a wrong secret, number %d: error = %q, want %q", revocationPath, i+1, got, "invalid_client")
				}
			}
			wantRevocationOK(t, tt.right.send(t, handler, accessToken))
		})
	}
}

// REQ-REVOKE-6, REQ-JWTAUTH-6, REQ-CORE-33: a client assertion
// authenticates one revocation request, as it does one token request: a
// second request with it fails with invalid_client and revokes nothing.
func TestRevocationAssertionReplay(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	k := jwtKey(jose.RS256)
	assertion := url.Values{"client_assertion_type": {jwtBearer}, "client_assertion": {signAssertion(t, k.alg, k.key, k.kid, assertionClaims())}}
	first, second := accessTokenOf(t, handler, "jwt"), accessTokenOf(t, handler, "jwt")

	wantRevocationOK(t, formAuth(assertion).send(t, handler, first))
	if got := revocationErrorCode(t, formAuth(assertion).send(t, handler, second), http.StatusUnauthorized); got != "invalid_client" {
		t.Errorf("POST %s with the assertion again error = %q, want %q", revocationPath, got, "invalid_client")
	}
	wantAccepted(t, handler, "after a replayed assertion", claimsOf(aliceProfile), []string{second})
}

// REQ-REVOKE-2, REQ-REVOKE-4, REQ-REVOKE-14, REQ-OAUTH-5, REQ-OAUTH-15: a
// revocation request without token, that repeats a parameter, or whose
// body is not a form fails with invalid_request, before its Client
// authenticates, so that a client assertion sent with it authenticates
// the corrected request. The endpoint answers no method but POST, and
// OPTIONS for a preflight.
func TestRevocationRequestErrors(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	k := jwtKey(jose.RS256)
	tests := []struct {
		name string
		edit func(url.Values)
	}{
		{name: "no token", edit: func(v url.Values) { v.Del("token") }},
		{name: "empty token", edit: func(v url.Values) { v.Set("token", "") }},
		{name: "repeated token", edit: func(v url.Values) { v.Add("token", v.Get("token")) }},
		{name: "repeated token_type_hint", edit: func(v url.Values) { v["token_type_hint"] = []string{"access_token", "access_token"} }},
		{name: "repeated client_assertion", edit: func(v url.Values) { v.Add("client_assertion", v.Get("client_assertion")) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			accessToken := accessTokenOf(t, handler, "jwt")
			form := revocationForm(accessToken, "")
			form.Set("client_assertion_type", jwtBearer)
			form.Set("client_assertion", signAssertion(t, k.alg, k.key, k.kid, assertionClaims()))
			malformed := maps.Clone(form)
			tt.edit(malformed)
			b := &browser{t: t, handler: handler}
			if got := revocationErrorCode(t, b.do(newRevocationRequest(t, "", "", malformed)), http.StatusBadRequest); got != "invalid_request" {
				t.Errorf("POST %s error = %q, want %q", revocationPath, got, "invalid_request")
			}
			wantAccepted(t, handler, "after a malformed revocation", claimsOf(aliceProfile), []string{accessToken})
			wantRevocationOK(t, b.do(newRevocationRequest(t, "", "", form)))
		})
	}

	t.Run("body not a form", func(t *testing.T) {
		t.Parallel()
		accessToken := accessTokenOf(t, handler, "rp")
		req := newRevocationRequest(t, "rp", rpSecret, revocationForm(accessToken, ""))
		req.Header.Set("Content-Type", "application/json")
		b := &browser{t: t, handler: handler}
		if got := revocationErrorCode(t, b.do(req), http.StatusBadRequest); got != "invalid_request" {
			t.Errorf("POST %s with a JSON body error = %q, want %q", revocationPath, got, "invalid_request")
		}
		wantAccepted(t, handler, "after a revocation with a JSON body", claimsOf(aliceProfile), []string{accessToken})
	})

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequestWithContext(t.Context(), method, "https://op.example"+revocationPath+"?token=x", http.NoBody)
			b := &browser{t: t, handler: handler}
			if resp := b.do(req); resp.status != http.StatusMethodNotAllowed {
				t.Errorf("%s %s status = %d, want %d", method, revocationPath, resp.status, http.StatusMethodNotAllowed)
			}
		})
	}
}
