package server

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
)

// The origins of the Clients of flowRegistry that the CORS tests send
// requests from: those of public's and rp's redirect URIs, and one no
// Client registered.
const (
	publicOrigin  = "https://public.example"
	rpOrigin      = "https://rp.example"
	unknownOrigin = "https://attacker.example"
)

// corsResponseHeaders are the CORS headers of a response that the tests
// compare, each "" when it is absent.
var corsResponseHeaders = []string{
	"Access-Control-Allow-Origin",
	"Access-Control-Allow-Methods",
	"Access-Control-Allow-Headers",
	"Access-Control-Max-Age",
	"Access-Control-Expose-Headers",
	"Access-Control-Allow-Credentials",
	"Vary",
}

// corsHeaders returns the value of each of corsResponseHeaders in resp.
func corsHeaders(resp response) map[string]string {
	got := make(map[string]string, len(corsResponseHeaders))
	for _, k := range corsResponseHeaders {
		got[k] = resp.header.Get(k)
	}
	return got
}

// noCORS returns the CORS headers of a response that a browser withholds
// from the application: none, but Vary when vary is not "".
func noCORS(vary string) map[string]string {
	h := make(map[string]string, len(corsResponseHeaders))
	for _, k := range corsResponseHeaders {
		h[k] = ""
	}
	h["Vary"] = vary
	return h
}

// withCORS returns noCORS("Origin") with the headers of set in addition.
func withCORS(set map[string]string) map[string]string {
	h := noCORS("Origin")
	maps.Copy(h, set)
	return h
}

// fromOrigin sends req with an Origin header of origin, unless it is "",
// as a browser does for a cross-origin request.
func fromOrigin(t *testing.T, handler http.Handler, req *http.Request, origin string) response {
	t.Helper()
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	b := &browser{t: t, handler: handler}
	return b.do(req)
}

// REQ-BROWSER-1, REQ-DISC-20, REQ-CORE-65, REQ-REVOKE-13: a preflight to
// the token or revocation endpoint is approved for the origin of a public
// Client's redirect URI, and one to UserInfo for that of any Client's,
// with the method and request headers each endpoint takes; any other
// origin, or an OPTIONS request that is not a preflight, gets no CORS
// headers. A preflight needs neither the database nor the signing keys.
func TestCORSPreflight(t *testing.T) {
	t.Parallel()

	handler := newFlowHandlerWithoutDatabase(t)
	tokenPreflight := map[string]string{
		"Access-Control-Allow-Methods": "POST",
		"Access-Control-Max-Age":       "3600",
	}
	userInfoPreflight := map[string]string{
		"Access-Control-Allow-Methods": "GET, POST",
		"Access-Control-Allow-Headers": "Authorization",
		"Access-Control-Max-Age":       "3600",
	}
	with := func(base map[string]string, origin string) map[string]string {
		h := withCORS(base)
		h["Access-Control-Allow-Origin"] = origin
		return h
	}
	tests := []struct {
		name      string
		path      string
		origin    string
		method    string // Access-Control-Request-Method, if any
		reqHeader string // Access-Control-Request-Headers, if any
		wantAllow string
		want      map[string]string
	}{
		{
			name: "token, public Client's origin", path: tokenPath, origin: publicOrigin, method: http.MethodPost,
			wantAllow: "OPTIONS, POST", want: with(tokenPreflight, publicOrigin),
		},
		{
			// A confidential Client cannot keep its secret in a browser.
			name: "token, confidential Client's origin", path: tokenPath, origin: rpOrigin, method: http.MethodPost,
			wantAllow: "OPTIONS, POST", want: noCORS("Origin"),
		},
		{
			name: "token, unknown origin", path: tokenPath, origin: unknownOrigin, method: http.MethodPost,
			wantAllow: "OPTIONS, POST", want: noCORS("Origin"),
		},
		{
			name: "token, not a preflight", path: tokenPath, origin: publicOrigin,
			wantAllow: "OPTIONS, POST", want: noCORS("Origin"),
		},
		{
			name: "revocation, public Client's origin", path: revocationPath, origin: publicOrigin, method: http.MethodPost,
			wantAllow: "OPTIONS, POST", want: with(tokenPreflight, publicOrigin),
		},
		{
			name: "revocation, confidential Client's origin", path: revocationPath, origin: rpOrigin, method: http.MethodPost,
			wantAllow: "OPTIONS, POST", want: noCORS("Origin"),
		},
		{
			name: "revocation, unknown origin", path: revocationPath, origin: unknownOrigin, method: http.MethodPost,
			wantAllow: "OPTIONS, POST", want: noCORS("Origin"),
		},
		{
			name: "UserInfo, confidential Client's origin", path: userInfoPath, origin: rpOrigin, method: http.MethodGet, reqHeader: "authorization",
			wantAllow: "GET, HEAD, OPTIONS, POST", want: with(userInfoPreflight, rpOrigin),
		},
		{
			name: "UserInfo, public Client's origin", path: userInfoPath, origin: publicOrigin, method: http.MethodPost, reqHeader: "authorization",
			wantAllow: "GET, HEAD, OPTIONS, POST", want: with(userInfoPreflight, publicOrigin),
		},
		{
			name: "UserInfo, unknown origin", path: userInfoPath, origin: unknownOrigin, method: http.MethodGet, reqHeader: "authorization",
			wantAllow: "GET, HEAD, OPTIONS, POST", want: noCORS("Origin"),
		},
		{
			// The origin a browser sends for a document with an opaque origin.
			name: "UserInfo, null origin", path: userInfoPath, origin: "null", method: http.MethodGet, reqHeader: "authorization",
			wantAllow: "GET, HEAD, OPTIONS, POST", want: noCORS("Origin"),
		},
		{
			name: "UserInfo, no origin", path: userInfoPath, method: http.MethodGet,
			wantAllow: "GET, HEAD, OPTIONS, POST", want: noCORS("Origin"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "https://op.example"+tt.path, http.NoBody)
			if tt.method != "" {
				req.Header.Set("Access-Control-Request-Method", tt.method)
			}
			if tt.reqHeader != "" {
				req.Header.Set("Access-Control-Request-Headers", tt.reqHeader)
			}
			resp := fromOrigin(t, handler, req, tt.origin)
			if resp.status != http.StatusNoContent {
				t.Errorf("OPTIONS %s from %q status = %d, want %d", tt.path, tt.origin, resp.status, http.StatusNoContent)
			}
			if got := resp.header.Get("Allow"); got != tt.wantAllow {
				t.Errorf("OPTIONS %s Allow = %q, want %q", tt.path, got, tt.wantAllow)
			}
			if diff := cmp.Diff(tt.want, corsHeaders(resp)); diff != "" {
				t.Errorf("OPTIONS %s from %q CORS headers mismatch (-want +got):\n%s", tt.path, tt.origin, diff)
			}
		})
	}
}

// REQ-BROWSER-1, REQ-DISC-20: a public Client redeems its code from the
// origin of its redirect URI, and reads the response, an error included.
// A request from any other origin, or from a confidential Client's
// origin, even one that names the Client by client_id, gets
// invalid_request without CORS headers, before the code is
// redeemed or a refresh token rotated: a token request is sent without a
// preflight, so its sender cannot read the response. So does one whose
// Client is not known, or that names two origins. A request with no
// origin, as a Client that is not a browser sends, is answered as before.
func TestTokenCORS(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	public := withCORS(map[string]string{"Access-Control-Allow-Origin": publicOrigin})
	send := func(t *testing.T, c pkceClient, form url.Values, origin string) response {
		t.Helper()
		return fromOrigin(t, handler, newTokenRequest(t, c.basic.id, c.basic.secret, form), origin)
	}

	t.Run("code", func(t *testing.T) {
		t.Parallel()
		form := publicPKCE.form(publicPKCE.code(t, handler), pkceVerifier)
		for _, origin := range []string{unknownOrigin, rpOrigin, "null"} {
			resp := send(t, publicPKCE, form, origin)
			if got := tokenErrorCode(t, resp, http.StatusBadRequest); got != "invalid_request" {
				t.Errorf("POST %s from %q error = %q, want %q", tokenPath, origin, got, "invalid_request")
			}
			if diff := cmp.Diff(noCORS("Origin"), corsHeaders(resp)); diff != "" {
				t.Errorf("POST %s from %q CORS headers mismatch (-want +got):\n%s", tokenPath, origin, diff)
			}
		}

		// The refused requests left the code to be redeemed.
		resp := send(t, publicPKCE, form, publicOrigin)
		tokenResponseOf(t, resp)
		if diff := cmp.Diff(public, corsHeaders(resp)); diff != "" {
			t.Errorf("POST %s from %q CORS headers mismatch (-want +got):\n%s", tokenPath, publicOrigin, diff)
		}

		// An error the application can read.
		resp = send(t, publicPKCE, form, publicOrigin)
		if got := tokenErrorCode(t, resp, http.StatusBadRequest); got != "invalid_grant" {
			t.Errorf("POST %s for a code redeemed before: error = %q, want %q", tokenPath, got, "invalid_grant")
		}
		if diff := cmp.Diff(public, corsHeaders(resp)); diff != "" {
			t.Errorf("POST %s from %q, failed: CORS headers mismatch (-want +got):\n%s", tokenPath, publicOrigin, diff)
		}
	})

	t.Run("Client not known", func(t *testing.T) {
		t.Parallel()
		form := publicPKCE.form(publicPKCE.code(t, handler), pkceVerifier)
		withoutID := maps.Clone(form)
		withoutID.Del("client_id")
		twoOrigins := newTokenRequest(t, "", "", form)
		twoOrigins.Header.Add("Origin", publicOrigin)
		twoOrigins.Header.Add("Origin", publicOrigin)
		for name, resp := range map[string]response{
			"without client_id":       send(t, publicPKCE, withoutID, publicOrigin),
			"with two Origin headers": fromOrigin(t, handler, twoOrigins, ""),
		} {
			if got := tokenErrorCode(t, resp, http.StatusBadRequest); got != "invalid_request" {
				t.Errorf("POST %s %s: error = %q, want %q", tokenPath, name, got, "invalid_request")
			}
			if diff := cmp.Diff(noCORS("Origin"), corsHeaders(resp)); diff != "" {
				t.Errorf("POST %s %s: CORS headers mismatch (-want +got):\n%s", tokenPath, name, diff)
			}
		}

		// The refused requests left the code to be redeemed.
		tokenResponseOf(t, send(t, publicPKCE, form, publicOrigin))
	})

	t.Run("refresh token", func(t *testing.T) {
		t.Parallel()
		refreshToken := publicPKCE.offlineTokens(t, handler, pkceVerifier, nil).RefreshToken
		form := refreshForm(refreshToken, "")
		form.Set("client_id", publicPKCE.clientID)
		resp := send(t, publicPKCE, form, unknownOrigin)
		if got := tokenErrorCode(t, resp, http.StatusBadRequest); got != "invalid_request" {
			t.Errorf("POST %s from %q error = %q, want %q", tokenPath, unknownOrigin, got, "invalid_request")
		}

		// The refused request left the refresh token unused: redeemed now,
		// it does not revoke its family as a reused one would.
		resp = send(t, publicPKCE, form, publicOrigin)
		if tokenResponseOf(t, resp).RefreshToken == "" {
			t.Errorf("POST %s from %q has no refresh_token", tokenPath, publicOrigin)
		}
		if diff := cmp.Diff(public, corsHeaders(resp)); diff != "" {
			t.Errorf("POST %s from %q CORS headers mismatch (-want +got):\n%s", tokenPath, publicOrigin, diff)
		}
	})

	t.Run("confidential Client", func(t *testing.T) {
		t.Parallel()
		form := rpNoPKCE.form(rpNoPKCE.code(t, handler), "")
		resp := send(t, rpNoPKCE, form, rpOrigin)
		if got := tokenErrorCode(t, resp, http.StatusBadRequest); got != "invalid_request" {
			t.Errorf("POST %s by rp from %q error = %q, want %q", tokenPath, rpOrigin, got, "invalid_request")
		}
		if diff := cmp.Diff(noCORS("Origin"), corsHeaders(resp)); diff != "" {
			t.Errorf("POST %s by rp from %q CORS headers mismatch (-want +got):\n%s", tokenPath, rpOrigin, diff)
		}

		// Naming itself by client_id as well, so that the request's Client
		// is known before it authenticates.
		named := maps.Clone(form)
		named.Set("client_id", "rp")
		resp = send(t, rpNoPKCE, named, rpOrigin)
		if got := tokenErrorCode(t, resp, http.StatusBadRequest); got != "invalid_request" {
			t.Errorf("POST %s by rp with its client_id from %q error = %q, want %q", tokenPath, rpOrigin, got, "invalid_request")
		}
		if diff := cmp.Diff(noCORS("Origin"), corsHeaders(resp)); diff != "" {
			t.Errorf("POST %s by rp with its client_id from %q CORS headers mismatch (-want +got):\n%s", tokenPath, rpOrigin, diff)
		}

		// Without an origin, as from rp's server.
		resp = send(t, rpNoPKCE, form, "")
		tokenResponseOf(t, resp)
		if diff := cmp.Diff(noCORS("Origin"), corsHeaders(resp)); diff != "" {
			t.Errorf("POST %s by rp without an origin: CORS headers mismatch (-want +got):\n%s", tokenPath, diff)
		}
	})
}

// REQ-REVOKE-13, REQ-BROWSER-1, REQ-DISC-20: a public Client revokes its
// token from the origin of its redirect URI, and reads the response, an
// error included. A request from any other origin, or from a confidential
// Client's origin, gets invalid_request without CORS headers, and revokes
// nothing, as at the token endpoint: a revocation request is sent without
// a preflight, so its sender cannot read the response. A request with no
// origin, as a Client that is not a browser sends, is answered as before.
func TestRevocationCORS(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	public := withCORS(map[string]string{"Access-Control-Allow-Origin": publicOrigin})
	send := func(t *testing.T, c pkceClient, token, origin string) response {
		t.Helper()
		return fromOrigin(t, handler, c.revocationRequest(t, token, ""), origin)
	}

	t.Run("public Client", func(t *testing.T) {
		t.Parallel()
		tokens := publicPKCE.offlineTokens(t, handler, pkceVerifier, nil)
		for _, origin := range []string{unknownOrigin, rpOrigin, "null"} {
			resp := send(t, publicPKCE, tokens.RefreshToken, origin)
			if got := revocationErrorCode(t, resp, http.StatusBadRequest); got != "invalid_request" {
				t.Errorf("POST %s from %q error = %q, want %q", revocationPath, origin, got, "invalid_request")
			}
			if diff := cmp.Diff(noCORS("Origin"), corsHeaders(resp)); diff != "" {
				t.Errorf("POST %s from %q CORS headers mismatch (-want +got):\n%s", revocationPath, origin, diff)
			}
		}
		// The refused requests revoked nothing.
		wantAccepted(t, handler, "after refused revocations", claimsOf(), []string{tokens.AccessToken})

		resp := send(t, publicPKCE, tokens.RefreshToken, publicOrigin)
		wantRevocationOK(t, resp)
		if diff := cmp.Diff(public, corsHeaders(resp)); diff != "" {
			t.Errorf("POST %s from %q CORS headers mismatch (-want +got):\n%s", revocationPath, publicOrigin, diff)
		}
		publicPKCE.wantRevoked(t, handler, tokens.RefreshToken, []string{tokens.AccessToken})

		// An error the application can read.
		resp = send(t, publicPKCE, "", publicOrigin)
		if got := revocationErrorCode(t, resp, http.StatusBadRequest); got != "invalid_request" {
			t.Errorf("POST %s without token: error = %q, want %q", revocationPath, got, "invalid_request")
		}
		if diff := cmp.Diff(public, corsHeaders(resp)); diff != "" {
			t.Errorf("POST %s from %q, failed: CORS headers mismatch (-want +got):\n%s", revocationPath, publicOrigin, diff)
		}
	})

	t.Run("confidential Client", func(t *testing.T) {
		t.Parallel()
		tokens := rpNoPKCE.offlineTokens(t, handler, "", nil)
		resp := send(t, rpNoPKCE, tokens.AccessToken, rpOrigin)
		if got := revocationErrorCode(t, resp, http.StatusBadRequest); got != "invalid_request" {
			t.Errorf("POST %s by rp from %q error = %q, want %q", revocationPath, rpOrigin, got, "invalid_request")
		}
		if diff := cmp.Diff(noCORS("Origin"), corsHeaders(resp)); diff != "" {
			t.Errorf("POST %s by rp from %q CORS headers mismatch (-want +got):\n%s", revocationPath, rpOrigin, diff)
		}
		wantAccepted(t, handler, "after a refused revocation", claimsOf(), []string{tokens.AccessToken})

		// Without an origin, as from rp's server.
		resp = send(t, rpNoPKCE, tokens.AccessToken, "")
		wantRevocationOK(t, resp)
		if diff := cmp.Diff(noCORS("Origin"), corsHeaders(resp)); diff != "" {
			t.Errorf("POST %s by rp without an origin: CORS headers mismatch (-want +got):\n%s", revocationPath, diff)
		}
	})
}

// REQ-CORE-65, REQ-BROWSER-1, REQ-DISC-20: UserInfo answers a request from
// the origin of a redirect URI of the Client the access token was issued
// to, confidential or public, and lets the application read the response
// and its WWW-Authenticate challenge, for a token since revoked too. A
// request from another origin gets invalid_request without CORS headers;
// so does one whose token pulsar did not sign, since its Client is not
// known. A request with no origin is answered as before.
func TestUserInfoCORS(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	rpToken, _ := tokensOf(t, tokenRequest(t, handler, "rp", rpSecret, codeForm(code(t, handler, authorizationParams()))))
	publicToken := tokenResponseOf(t, publicPKCE.redeem(t, handler, publicPKCE.form(publicPKCE.code(t, handler), pkceVerifier))).AccessToken
	// Redeeming a code again revokes its access token (REQ-OAUTH-29).
	revokedForm := codeForm(code(t, handler, authorizationParams()))
	revokedToken, _ := tokensOf(t, tokenRequest(t, handler, "rp", rpSecret, revokedForm))
	tokenRequest(t, handler, "rp", rpSecret, revokedForm)

	readable := func(origin string) map[string]string {
		return withCORS(map[string]string{"Access-Control-Allow-Origin": origin, "Access-Control-Expose-Headers": "WWW-Authenticate"})
	}
	tests := []struct {
		name       string
		token      string
		origin     string
		wantStatus int
		wantError  string // the error code of the challenge, for a status other than 200
		want       map[string]string
	}{
		{name: "confidential Client's token from its origin", token: rpToken, origin: rpOrigin, wantStatus: http.StatusOK, want: readable(rpOrigin)},
		{name: "public Client's token from its origin", token: publicToken, origin: publicOrigin, wantStatus: http.StatusOK, want: readable(publicOrigin)},
		{name: "revoked token from its Client's origin", token: revokedToken, origin: rpOrigin, wantStatus: http.StatusUnauthorized, wantError: "invalid_token", want: readable(rpOrigin)},
		{name: "another Client's origin", token: rpToken, origin: publicOrigin, wantStatus: http.StatusBadRequest, wantError: "invalid_request", want: noCORS("Origin")},
		{name: "unknown origin", token: rpToken, origin: unknownOrigin, wantStatus: http.StatusBadRequest, wantError: "invalid_request", want: noCORS("Origin")},
		{name: "token pulsar did not sign", token: "not-a-token", origin: rpOrigin, wantStatus: http.StatusUnauthorized, wantError: "invalid_token", want: noCORS("Origin")},
		{name: "no origin", token: rpToken, wantStatus: http.StatusOK, want: noCORS("Origin")},
	}
	for _, tt := range tests {
		for _, s := range []tokenSending{getHeader, postHeader, postBody} {
			t.Run(tt.name+"/"+s.name, func(t *testing.T) {
				t.Parallel()
				resp := fromOrigin(t, handler, newUserInfoRequest(t, s, tt.token), tt.origin)
				if tt.wantStatus == http.StatusOK {
					userInfoClaims(t, resp)
				} else if got := userInfoError(t, resp, tt.wantStatus); got != tt.wantError {
					t.Errorf("UserInfo %s from %q error = %q, want %q", s.name, tt.origin, got, tt.wantError)
				}
				if diff := cmp.Diff(tt.want, corsHeaders(resp)); diff != "" {
					t.Errorf("UserInfo %s from %q CORS headers mismatch (-want +got):\n%s", s.name, tt.origin, diff)
				}
			})
		}
	}
}

// REQ-BCP-12, REQ-DISC-21: the authorization endpoint, to which a Client
// redirects the browser rather than sending a request itself, sends no
// CORS headers, and answers no preflight.
func TestAuthorizationNoCORS(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	params := authorizationParams().Encode()
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		var req *http.Request
		switch method {
		case http.MethodGet:
			req = httptest.NewRequestWithContext(t.Context(), method, "https://op.example"+authorizationPath+"?"+params, http.NoBody)
		case http.MethodPost:
			req = httptest.NewRequestWithContext(t.Context(), method, "https://op.example"+authorizationPath, strings.NewReader(params))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		resp := fromOrigin(t, handler, req, rpOrigin)
		if diff := cmp.Diff(noCORS(""), corsHeaders(resp)); diff != "" {
			t.Errorf("%s %s from %q CORS headers mismatch (-want +got):\n%s", method, authorizationPath, rpOrigin, diff)
		}
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "https://op.example"+authorizationPath, http.NoBody)
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)
	resp := fromOrigin(t, handler, req, rpOrigin)
	if resp.status != http.StatusMethodNotAllowed {
		t.Errorf("OPTIONS %s status = %d, want %d", authorizationPath, resp.status, http.StatusMethodNotAllowed)
	}
	if diff := cmp.Diff(noCORS(""), corsHeaders(resp)); diff != "" {
		t.Errorf("OPTIONS %s CORS headers mismatch (-want +got):\n%s", authorizationPath, diff)
	}
}
