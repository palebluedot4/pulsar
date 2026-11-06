package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"

	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
)

// tokenResponse is a successful token response (RFC 6749 §5.1).
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// tokenResponseOf returns the token response in resp, failing the test
// unless it is successful and has the headers of RFC 6749 §5.1.
func tokenResponseOf(t *testing.T, resp response) tokenResponse {
	t.Helper()
	if resp.status != http.StatusOK {
		t.Fatalf("POST %s status = %d, want %d; body %q", tokenPath, resp.status, http.StatusOK, resp.body)
	}
	wantHeader := map[string]string{"Content-Type": "application/json", "Cache-Control": "no-store", "Pragma": "no-cache"}
	if diff := cmp.Diff(wantHeader, headers(resp.header, wantHeader)); diff != "" {
		t.Errorf("POST %s headers mismatch (-want +got):\n%s", tokenPath, diff)
	}
	var r tokenResponse
	if err := json.Unmarshal([]byte(resp.body), &r); err != nil {
		t.Fatalf("POST %s body %q is not a token response: %v", tokenPath, resp.body, err)
	}
	return r
}

// offlineTokens signs alice in through c's authorization request for
// offline access, with the parameters of set in addition, allows it on the
// consent page, and returns the response to the code's redemption with
// verifier, unless it is "".
func (c pkceClient) offlineTokens(t *testing.T, handler http.Handler, verifier string, set url.Values) tokenResponse {
	t.Helper()
	params := clientParams(c.clientID, c.redirectURI)
	params.Set("scope", "openid offline_access")
	params.Set("prompt", "consent")
	if c.challenge != "" {
		withChallenge(params, c.challenge)
	}
	maps.Copy(params, set)
	r := tokenResponseOf(t, c.redeem(t, handler, c.form(code(t, handler, params), verifier)))
	if r.RefreshToken == "" {
		t.Fatalf("POST %s for a code issued with offline access has no refresh_token", tokenPath)
	}
	return r
}

// refreshForm returns the form of a token request that redeems
// refreshToken, for scope unless it is "".
func refreshForm(refreshToken, scope string) url.Values {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
	if scope != "" {
		form.Set("scope", scope)
	}
	return form
}

// refresh sends a token request from the Client that redeems refreshToken,
// for scope unless it is "".
func (c pkceClient) refresh(t *testing.T, handler http.Handler, refreshToken, scope string) response {
	t.Helper()
	form := refreshForm(refreshToken, scope)
	if c.basic.id == "" {
		form.Set("client_id", c.clientID)
	}
	return c.redeem(t, handler, form)
}

// wantAtLeast160Bits fails the test unless token, which name describes,
// is at least 160 bits in base64url, so that guessing one is as unlikely
// as RFC 6749 §10.10 recommends.
func wantAtLeast160Bits(t *testing.T, name, token string) {
	t.Helper()
	if raw, err := base64.RawURLEncoding.DecodeString(token); err != nil || len(raw) < 20 {
		t.Errorf("%s = %q, want at least 160 bits in base64url", name, token)
	}
}

// atHash returns the at_hash of accessToken (OpenID Connect Core 1.0
// §3.1.3.6).
func atHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// REQ-OAUTH-13, REQ-OAUTH-21, REQ-OAUTH-33, REQ-OAUTH-35, REQ-OAUTH-37,
// REQ-OAUTH-40, REQ-OAUTH-41, REQ-BCP-9, REQ-CORE-52, REQ-CORE-55,
// REQ-CORE-56, REQ-CORE-57, REQ-CORE-58, REQ-CORE-59, REQ-CORE-60,
// REQ-CORE-61, REQ-CORE-62, REQ-CORE-63, REQ-AT-1, REQ-AT-2, REQ-AT-3,
// REQ-AT-4, REQ-AT-5: a confidential or a public Client redeems its
// refresh token for a new access token, ID token and refresh token, and
// then redeems the new refresh token in turn. Each access token is an RFC
// 9068 JWT valid for ten minutes, and UserInfo returns the claims of its
// scopes. Each ID token has the original's iss, sub, aud and auth_time, no
// azp as the original has none, no nonce, a new iat, and the claims
// requested for the ID token. Each refresh token is new, and the one it
// replaces is refused.
func TestRefreshToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		client   pkceClient
		verifier string
	}{
		{name: "confidential Client", client: rpNoPKCE},
		{name: "public Client", client: publicPKCE, verifier: pkceVerifier},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
			synctest.Test(t, func(t *testing.T) {
				handler := newBubbleFlowHandler(t, databaseURL)
				first := tt.client.offlineTokens(t, handler, tt.verifier, url.Values{
					"scope":  {"openid email offline_access"},
					"claims": {`{"id_token": {"phone_number": null}}`},
				})
				original := verify(t, handler, first.IDToken).claims
				if _, ok := original["nonce"]; !ok {
					t.Fatalf("ID token from the code has no nonce, so the test cannot show the refreshed one leaves it out")
				}

				redeemed := []string{first.RefreshToken}
				refreshToken := first.RefreshToken
				for _, step := range []string{"first refresh", "second refresh"} {
					time.Sleep(time.Minute)
					now := time.Now()
					got := tokenResponseOf(t, tt.client.refresh(t, handler, refreshToken, ""))

					wantAtLeast160Bits(t, step+": refresh_token", got.RefreshToken)
					if slices.Contains(redeemed, got.RefreshToken) {
						t.Errorf("%s: refresh_token = %q, one already redeemed; want a new one", step, got.RefreshToken)
					}
					want := tokenResponse{TokenType: "Bearer", ExpiresIn: 600, Scope: "openid email offline_access"}
					gotFields := tokenResponse{TokenType: got.TokenType, ExpiresIn: got.ExpiresIn, Scope: got.Scope}
					if diff := cmp.Diff(want, gotFields); diff != "" {
						t.Errorf("%s: token response mismatch (-want +got):\n%s", step, diff)
					}

					wantID := map[string]any{
						"iss":          original["iss"],
						"sub":          original["sub"],
						"aud":          original["aud"],
						"auth_time":    original["auth_time"],
						"iat":          float64(now.Unix()),
						"exp":          float64(now.Add(10 * time.Minute).Unix()),
						"at_hash":      atHash(got.AccessToken),
						"phone_number": "+1 555 0100",
					}
					if diff := cmp.Diff(wantID, verify(t, handler, got.IDToken).claims); diff != "" {
						t.Errorf("%s: ID token claims mismatch (-want +got):\n%s", step, diff)
					}

					at := verify(t, handler, got.AccessToken)
					wantAT := map[string]any{
						"iss": loginIssuer, "aud": loginIssuer, "sub": aliceSubject, "client_id": tt.client.clientID,
						"iat": float64(now.Unix()), "exp": float64(now.Add(10 * time.Minute).Unix()),
						"jti": at.claims["jti"], "scope": "openid email offline_access",
					}
					if diff := cmp.Diff(wantAT, at.claims); diff != "" {
						t.Errorf("%s: access token claims mismatch (-want +got):\n%s", step, diff)
					}
					if at.typ != "at+jwt" {
						t.Errorf("%s: access token typ = %q, want %q", step, at.typ, "at+jwt")
					}
					if diff := cmp.Diff(claimsOf(aliceEmail), userInfoClaims(t, userInfo(t, handler, getHeader, got.AccessToken))); diff != "" {
						t.Errorf("%s: UserInfo claims mismatch (-want +got):\n%s", step, diff)
					}

					redeemed = append(redeemed, got.RefreshToken)
					refreshToken = got.RefreshToken
				}

				if got := tokenErrorCode(t, tt.client.refresh(t, handler, first.RefreshToken, ""), http.StatusBadRequest); got != "invalid_grant" {
					t.Errorf("POST %s with a refresh token already redeemed error = %q, want %q", tokenPath, got, "invalid_grant")
				}
			})
		})
	}
}

// REQ-OAUTH-36, REQ-OAUTH-37, REQ-BCP-8, REQ-AT-4, REQ-CORE-43: a refresh
// without scope is for the scope originally granted; one for a narrower
// scope issues an access token for that scope alone, which UserInfo
// answers with that scope's claims, and with those the claims parameter
// requested from UserInfo, and a refresh token for the scope originally
// granted, which the next refresh without scope shows.
func TestRefreshTokenScope(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	const granted = "openid email offline_access"
	tests := []struct {
		name         string
		claims       string // the authorization request's claims parameter, if any
		scope        string
		wantScope    string
		wantUserInfo map[string]any
	}{
		{name: "omitted", wantScope: granted, wantUserInfo: claimsOf(aliceEmail)},
		{name: "the same, in another order", scope: "offline_access email openid", wantScope: "offline_access email openid", wantUserInfo: claimsOf(aliceEmail)},
		{name: "narrower", scope: "openid", wantScope: "openid", wantUserInfo: claimsOf()},
		{name: "narrower, with a value repeated", scope: "openid email email", wantScope: "openid email", wantUserInfo: claimsOf(aliceEmail)},
		{
			name: "narrower, with a claim requested from UserInfo", claims: `{"userinfo": {"phone_number": null}}`,
			scope: "openid", wantScope: "openid", wantUserInfo: claimsOf(map[string]any{"phone_number": "+1 555 0100"}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			set := url.Values{"scope": {granted}}
			if tt.claims != "" {
				set.Set("claims", tt.claims)
			}
			first := rpNoPKCE.offlineTokens(t, handler, "", set)
			got := tokenResponseOf(t, rpNoPKCE.refresh(t, handler, first.RefreshToken, tt.scope))
			if got.Scope != tt.wantScope {
				t.Errorf("POST %s for scope %q: scope = %q, want %q", tokenPath, tt.scope, got.Scope, tt.wantScope)
			}
			if diff := cmp.Diff(tt.wantScope, verify(t, handler, got.AccessToken).claims["scope"]); diff != "" {
				t.Errorf("POST %s for scope %q: access token scope mismatch (-want +got):\n%s", tokenPath, tt.scope, diff)
			}
			if diff := cmp.Diff(tt.wantUserInfo, userInfoClaims(t, userInfo(t, handler, getHeader, got.AccessToken))); diff != "" {
				t.Errorf("UserInfo for scope %q: claims mismatch (-want +got):\n%s", tt.scope, diff)
			}

			next := tokenResponseOf(t, rpNoPKCE.refresh(t, handler, got.RefreshToken, ""))
			if next.Scope != granted {
				t.Errorf("POST %s with the refresh token issued for scope %q, without scope: scope = %q, want %q", tokenPath, tt.scope, next.Scope, granted)
			}
		})
	}
}

// REQ-OAUTH-36, REQ-OAUTH-38, REQ-BCP-8: a refresh for a scope that
// includes any scope not originally granted fails with invalid_scope, and
// leaves the refresh token to be redeemed.
func TestRefreshTokenScopeNotGranted(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	for _, scope := range []string{"openid email offline_access phone", "openid profile", "openid unknown"} {
		t.Run(scope, func(t *testing.T) {
			t.Parallel()
			first := rpNoPKCE.offlineTokens(t, handler, "", url.Values{"scope": {"openid email offline_access"}})
			if got := tokenErrorCode(t, rpNoPKCE.refresh(t, handler, first.RefreshToken, scope), http.StatusBadRequest); got != "invalid_scope" {
				t.Errorf("POST %s for scope %q error = %q, want %q", tokenPath, scope, got, "invalid_scope")
			}
			tokenResponseOf(t, rpNoPKCE.refresh(t, handler, first.RefreshToken, ""))
		})
	}
}

// REQ-OAUTH-19, REQ-OAUTH-32, REQ-OAUTH-34, REQ-OAUTH-39, REQ-CORE-56:
// a refresh token presented by a Client other than the one it was issued
// to fails with 400 and invalid_grant, whichever way that Client
// authenticates, and stays the other Client's to redeem.
func TestRefreshTokenOtherClient(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	rs := jwtKey(jose.RS256)
	tests := []struct {
		name     string
		owner    pkceClient
		verifier string
		// The request of the other Client: the credentials it sends by HTTP
		// Basic authentication, if any, and what its form adds.
		basic credentials
		form  func(t *testing.T) url.Values
	}{
		{name: "by client_secret_basic", owner: publicPKCE, verifier: pkceVerifier, basic: credentials{"rp", rpSecret}},
		{name: "by client_secret_basic, another confidential Client", owner: rpNoPKCE, basic: credentials{"other", otherSecret}},
		{
			name: "by client_secret_post", owner: rpNoPKCE,
			form: func(*testing.T) url.Values { return url.Values{"client_id": {"post"}, "client_secret": {postSecret}} },
		},
		{
			name: "by private_key_jwt", owner: rpNoPKCE,
			form: func(t *testing.T) url.Values {
				t.Helper()
				return url.Values{"client_assertion_type": {jwtBearer}, "client_assertion": {signAssertion(t, rs.alg, rs.key, rs.kid, assertionClaims())}}
			},
		},
		{
			name: "as a public Client", owner: rpNoPKCE,
			form: func(*testing.T) url.Values { return url.Values{"client_id": {"public"}} },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			first := tt.owner.offlineTokens(t, handler, tt.verifier, nil)
			form := refreshForm(first.RefreshToken, "")
			if tt.form != nil {
				maps.Copy(form, tt.form(t))
			}
			if got := tokenErrorCode(t, tokenRequest(t, handler, tt.basic.id, tt.basic.secret, form), http.StatusBadRequest); got != "invalid_grant" {
				t.Errorf("POST %s with another Client's refresh token error = %q, want %q", tokenPath, got, "invalid_grant")
			}
			tokenResponseOf(t, tt.owner.refresh(t, handler, first.RefreshToken, ""))
		})
	}
}

// REQ-OAUTH-5, REQ-OAUTH-14, REQ-OAUTH-15, REQ-OAUTH-19, REQ-OAUTH-26,
// REQ-OAUTH-27, REQ-OAUTH-33, REQ-OAUTH-35, REQ-CORE-55, REQ-CORE-64: a
// refresh request fails, in the JSON form of RFC 6749 §5.2, when it has no
// refresh token or repeats a parameter, when its Client does not
// authenticate by its registered method, and when its refresh token is
// unknown.
func TestRefreshTokenErrors(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	tests := []struct {
		name       string
		owner      pkceClient
		verifier   string
		basic      credentials
		edit       func(url.Values)
		wantStatus int
		wantError  string
	}{
		{
			name: "no refresh_token", owner: rpNoPKCE, basic: rpNoPKCE.basic,
			edit:       func(v url.Values) { v.Del("refresh_token") },
			wantStatus: http.StatusBadRequest, wantError: "invalid_request",
		},
		{
			name: "repeated refresh_token", owner: rpNoPKCE, basic: rpNoPKCE.basic,
			edit:       func(v url.Values) { v.Add("refresh_token", v.Get("refresh_token")) },
			wantStatus: http.StatusBadRequest, wantError: "invalid_request",
		},
		{
			name: "repeated scope", owner: rpNoPKCE, basic: rpNoPKCE.basic,
			edit:       func(v url.Values) { v["scope"] = []string{"openid", "openid"} },
			wantStatus: http.StatusBadRequest, wantError: "invalid_request",
		},
		{
			name: "unknown refresh token", owner: rpNoPKCE, basic: rpNoPKCE.basic,
			edit:       func(v url.Values) { v.Set("refresh_token", "unknown") },
			wantStatus: http.StatusBadRequest, wantError: "invalid_grant",
		},
		{
			name: "wrong secret", owner: rpNoPKCE, basic: credentials{"rp", otherSecret},
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		{
			name: "confidential Client without authentication", owner: rpNoPKCE,
			edit:       func(v url.Values) { v.Set("client_id", "rp") },
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		{
			name: "confidential Client by a method other than the registered one", owner: rpNoPKCE,
			edit:       func(v url.Values) { v.Set("client_id", "rp"); v.Set("client_secret", rpSecret) },
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		{
			name: "public Client without client_id", owner: publicPKCE, verifier: pkceVerifier,
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			form := refreshForm(tt.owner.offlineTokens(t, handler, tt.verifier, nil).RefreshToken, "")
			if tt.edit != nil {
				tt.edit(form)
			}
			if got := tokenErrorCode(t, tokenRequest(t, handler, tt.basic.id, tt.basic.secret, form), tt.wantStatus); got != tt.wantError {
				t.Errorf("POST %s error = %q, want %q", tokenPath, got, tt.wantError)
			}
		})
	}
}

// REQ-OAUTH-19, REQ-OAUTH-35, REQ-BCP-10: a Refresh Token Family ends 30
// days after its code is redeemed, with no limit for inactivity: a refresh
// token is redeemed until then, however long since the last refresh, and
// after that fails with invalid_grant, however recent the last refresh.
func TestRefreshTokenFamilyExpiry(t *testing.T) {
	t.Parallel()

	const day = 24 * time.Hour
	tests := []struct {
		name string
		// waits are the times between the code's redemption and the first
		// refresh, and between each refresh and the next. Every refresh but
		// the last succeeds.
		waits      []time.Duration
		wantStatus int
	}{
		{name: "inactive until a second before the end", waits: []time.Duration{30*day - time.Second}, wantStatus: http.StatusOK},
		{name: "inactive until the end", waits: []time.Duration{30 * day}, wantStatus: http.StatusBadRequest},
		{name: "refreshed a day before the end", waits: []time.Duration{29 * day, day}, wantStatus: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
			synctest.Test(t, func(t *testing.T) {
				handler := newBubbleFlowHandler(t, databaseURL)
				// The code is redeemed 30 seconds after it is issued, so that
				// the 30 days are seen to run from its redemption.
				c := code(t, handler, offlineAccessParams())
				time.Sleep(30 * time.Second)
				refreshToken := tokenResponseOf(t, tokenRequest(t, handler, "rp", rpSecret, codeForm(c))).RefreshToken
				last := len(tt.waits) - 1
				for _, wait := range tt.waits[:last] {
					time.Sleep(wait)
					refreshToken = tokenResponseOf(t, rpNoPKCE.refresh(t, handler, refreshToken, "")).RefreshToken
				}
				time.Sleep(tt.waits[last])

				resp := rpNoPKCE.refresh(t, handler, refreshToken, "")
				if tt.wantStatus == http.StatusOK {
					tokenResponseOf(t, resp)
					return
				}
				if got := tokenErrorCode(t, resp, tt.wantStatus); got != "invalid_grant" {
					t.Errorf("POST %s error = %q, want %q", tokenPath, got, "invalid_grant")
				}
			})
		})
	}
}

// REQ-OAUTH-35, REQ-BCP-9: of token requests that redeem one refresh
// token at once, exactly one succeeds, and the others fail with
// invalid_grant.
func TestRefreshTokenConcurrentRedemption(t *testing.T) {
	t.Parallel()

	const requests = 8
	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	refreshToken := rpNoPKCE.offlineTokens(t, handler, "", nil).RefreshToken
	resps := make([]response, requests)
	var wg sync.WaitGroup
	for i := range requests {
		wg.Go(func() {
			resps[i] = rpNoPKCE.refresh(t, handler, refreshToken, "")
		})
	}
	wg.Wait()
	counts := map[int]int{}
	for _, r := range resps {
		counts[r.status]++
		if r.status != http.StatusOK {
			if got := tokenErrorCode(t, r, http.StatusBadRequest); got != "invalid_grant" {
				t.Errorf("POST %s of a refresh token redeemed at once by another request error = %q, want %q", tokenPath, got, "invalid_grant")
			}
		}
	}
	want := map[int]int{http.StatusOK: 1, http.StatusBadRequest: requests - 1}
	if diff := cmp.Diff(want, counts); diff != "" {
		t.Errorf("statuses of %d concurrent redemptions of one refresh token mismatch (-want +got):\n%s", requests, diff)
	}
}
