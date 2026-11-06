package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
)

// errorResponse returns the parameters of the error response resp
// redirects to at rp's redirect URI, without error_description, failing
// the test if it redirects anywhere else.
func errorResponse(t *testing.T, resp response) url.Values {
	t.Helper()
	callback := location(t, resp)
	if got := withoutQuery(callback); got != rpRedirectURI {
		t.Fatalf("redirected to %q, want %q", callback, rpRedirectURI)
	}
	got := callback.Query()
	got.Del("error_description")
	return got
}

// REQ-CORE-14, REQ-CORE-29, REQ-CORE-30, REQ-OAUTH-9, REQ-ISS-2: a request
// with prompt=none never shows a page. Without a Login Session it gets
// login_required, and without a Consent that covers it consent_required;
// with both it gets a code.
func TestPromptNone(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(b *browser) // signs b in, or not, and gives Consent, or not
		want  url.Values       // the error response; nil for a code
	}{
		{
			name:  "no Login Session",
			setup: func(*browser) {},
			want:  url.Values{"error": {"login_required"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}},
		},
		{
			name:  "no Consent",
			setup: func(b *browser) { parseConsentPage(b.t, b.signIn(b.authorize(http.MethodGet, authorizationParams()))) },
			want:  url.Values{"error": {"consent_required"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}},
		},
		{
			name: "Consent for fewer scopes",
			setup: func(b *browser) {
				wantCode(b.t, b.decide(b.signIn(b.authorize(http.MethodGet, withScope("openid"))), "allow"), "request for openid")
			},
			want: url.Values{"error": {"consent_required"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}},
		},
		{
			name: "Login Session and Consent",
			setup: func(b *browser) {
				wantCode(b.t, b.decide(b.signIn(b.authorize(http.MethodGet, authorizationParams())), "allow"), "first request")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := &browser{t: t, handler: newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))}
			tt.setup(b)
			params := authorizationParams()
			params.Set("prompt", "none")
			resp := b.authorize(http.MethodGet, params)
			if tt.want == nil {
				wantCode(t, resp, "prompt=none")
				return
			}
			if diff := cmp.Diff(tt.want, errorResponse(t, resp)); diff != "" {
				t.Errorf("prompt=none error response mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// idToken redeems the code that resp carries and returns the ID token.
func idToken(t *testing.T, handler http.Handler, resp response) string {
	t.Helper()
	code := location(t, resp).Query().Get("code")
	tokens := tokenRequest(t, handler, "rp", rpSecret, codeForm(code))
	if tokens.status != http.StatusOK {
		t.Fatalf("POST %s status = %d, want %d; body %q", tokenPath, tokens.status, http.StatusOK, tokens.body)
	}
	var body struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal([]byte(tokens.body), &body); err != nil {
		t.Fatalf("POST %s body is not a token response: %v", tokenPath, err)
	}
	return body.IDToken
}

// authTime redeems the code that resp carries and returns the auth_time of
// the ID token, in seconds since the epoch.
func authTime(t *testing.T, handler http.Handler, resp response) int64 {
	t.Helper()
	at, ok := verify(t, handler, idToken(t, handler, resp)).claims["auth_time"].(float64)
	if !ok {
		t.Fatalf("ID token has no numeric auth_time")
	}
	return int64(at)
}

// reauthenticate follows resp, a redirect to the login page, which must
// show the form even though the browser is signed in, signs in there as
// alice, and returns the response of the authorization endpoint it
// resumes at.
func (b *browser) reauthenticate(resp response) response {
	b.t.Helper()
	loginURL := location(b.t, resp)
	if loginURL.Path != loginPath {
		b.t.Fatalf("redirected to %q, want the login page %q", loginURL, loginPath)
	}
	page := b.send(http.MethodGet, loginURL.RequestURI(), nil)
	if page.status != http.StatusOK || !strings.Contains(page.body, `name="password"`) {
		b.t.Fatalf("GET %s status = %d, want %d and the login form; Location %q", loginURL.RequestURI(), page.status, http.StatusOK, page.header.Get("Location"))
	}
	return b.signIn(resp)
}

// REQ-CORE-15, REQ-CORE-17, REQ-CORE-20, REQ-CORE-13: prompt=login,
// prompt=select_account, max_age=0 and a max_age the Login Session's
// authentication has exceeded each send a signed-in End-User to the login
// form; signing in there returns them to the Client with a code, not to
// the form again, and the ID token's auth_time is the new login's. A
// max_age not exceeded asks for nothing.
func TestForcedLogin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		params    []string      // name and value pairs added to the request
		wait      time.Duration // between the first login and the request
		wantLogin bool
	}{
		{name: "prompt=login", params: []string{"prompt", "login"}, wait: time.Second, wantLogin: true},
		{name: "prompt=select_account", params: []string{"prompt", "select_account"}, wait: time.Second, wantLogin: true},
		{name: "prompt=login consent", params: []string{"prompt", "login consent"}, wait: time.Second, wantLogin: true},
		{name: "max_age=0", params: []string{"max_age", "0"}, wantLogin: true},
		{name: "max_age exceeded", params: []string{"max_age", "60"}, wait: 61 * time.Second, wantLogin: true},
		{name: "max_age not exceeded", params: []string{"max_age", "60"}, wait: 60 * time.Second},
		{name: "max_age beyond int64", params: []string{"max_age", "99999999999999999999"}, wait: 20 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
			synctest.Test(t, func(t *testing.T) {
				handler := newBubbleFlowHandler(t, databaseURL)
				start := time.Now().Unix()
				b := &browser{t: t, handler: handler}
				wantCode(t, b.decide(b.signIn(b.authorize(http.MethodGet, authorizationParams())), "allow"), "first request")
				time.Sleep(tt.wait)

				params := withScope("openid profile", tt.params...)
				resp := b.authorize(http.MethodGet, params)
				want := start
				if tt.wantLogin {
					resp = b.reauthenticate(resp)
					if params.Get("prompt") == "login consent" {
						resp = b.decide(resp, "allow")
					}
					want = start + int64(tt.wait/time.Second)
				}
				wantCode(t, resp, tt.name)
				if got := authTime(t, handler, resp); got != want {
					t.Errorf("%s: ID token auth_time = %d, want %d", tt.name, got, want)
				}
			})
		})
	}
}

// REQ-CORE-15, REQ-CORE-20: a forced login is satisfied only by a login on
// the login form, in the same browser, for the same request, once.
// Visiting the form without signing in, a login for another request, or a
// request replayed after its login was used all send the browser to the
// form again.
func TestForcedLoginCannotBeForged(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// forge acts on b, signed in as alice with a Consent, before the
		// request with prompt=login that must still be sent to log in.
		forge func(b *browser, params url.Values)
	}{
		{
			name: "parameters added",
			forge: func(_ *browser, params url.Values) {
				params.Set("auth_time", "4102444800")
				params.Set("max_age", "100000")
			},
		},
		{
			name: "login page visited without signing in",
			forge: func(b *browser, params url.Values) {
				b.send(http.MethodGet, loginPath+"?"+params.Encode(), nil)
			},
		},
		{
			name: "login for another request",
			forge: func(b *browser, _ url.Values) {
				other := withScope("openid profile", "prompt", "login", "state", "other")
				b.reauthenticate(b.authorize(http.MethodGet, other))
			},
		},
		{
			name: "replayed after its login",
			forge: func(b *browser, params url.Values) {
				t := b.t
				wantCode(t, b.reauthenticate(b.authorize(http.MethodGet, params)), "first request with prompt=login")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := &browser{t: t, handler: newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))}
			wantCode(t, b.decide(b.signIn(b.authorize(http.MethodGet, authorizationParams())), "allow"), "first request")
			params := withScope("openid profile", "prompt", "login")
			tt.forge(b, params)
			if u := location(t, b.authorize(http.MethodGet, params)); u.Path != loginPath {
				t.Errorf("prompt=login request redirected to %q, want the login page %q", u, loginPath)
			}
		})
	}
}

// REQ-CORE-14, REQ-CORE-20: with prompt=none, a max_age the Login
// Session's authentication has exceeded gets login_required rather than
// the login page.
func TestPromptNoneMaxAge(t *testing.T) {
	t.Parallel()

	databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
	synctest.Test(t, func(t *testing.T) {
		b := &browser{t: t, handler: newBubbleFlowHandler(t, databaseURL)}
		wantCode(t, b.decide(b.signIn(b.authorize(http.MethodGet, authorizationParams())), "allow"), "first request")
		time.Sleep(11 * time.Second)
		resp := b.authorize(http.MethodGet, withScope("openid profile", "prompt", "none", "max_age", "10"))
		want := url.Values{"error": {"login_required"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}}
		if diff := cmp.Diff(want, errorResponse(t, resp)); diff != "" {
			t.Errorf("prompt=none with max_age exceeded error response mismatch (-want +got):\n%s", diff)
		}
	})
}

// REQ-CORE-25: login_hint fills the login form's username field, escaped
// as any other value the page shows.
func TestLoginHint(t *testing.T) {
	t.Parallel()

	handler := newFlowHandlerWithoutDatabase(t)
	tests := []struct {
		hint string
		want string // in the page's body
	}{
		{hint: "alice", want: `value="alice"`},
		{hint: `"><script>x</script>`, want: `value="&#34;&gt;&lt;script&gt;x&lt;/script&gt;"`},
	}
	for _, tt := range tests {
		t.Run(tt.hint, func(t *testing.T) {
			t.Parallel()
			b := &browser{t: t, handler: handler}
			loginURL := location(t, b.authorize(http.MethodGet, withScope("openid", "login_hint", tt.hint)))
			resp := b.send(http.MethodGet, loginURL.RequestURI(), nil)
			if resp.status != http.StatusOK || !strings.Contains(resp.body, `name="username"`) {
				t.Fatalf("GET %s status = %d, want %d and the login form", loginURL.RequestURI(), resp.status, http.StatusOK)
			}
			if !strings.Contains(resp.body, tt.want) {
				t.Errorf("GET %s body = %q, want it to contain %q", loginURL.RequestURI(), resp.body, tt.want)
			}
		})
	}
}

// REQ-CORE-21, REQ-CORE-22, REQ-CORE-23, REQ-CORE-26: display, ui_locales,
// claims_locales and acr_values, with values pulsar supports or not, are
// accepted without error, and no ID token carries acr.
func TestAcceptedParameters(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	tests := []struct {
		name   string
		params []string
	}{
		{name: "display=popup", params: []string{"display", "popup"}},
		{name: "display unknown", params: []string{"display", "x-unknown"}},
		{name: "ui_locales", params: []string{"ui_locales", "fr-CA fr en"}},
		{name: "claims_locales", params: []string{"claims_locales", "ja-Kana-JP de"}},
		{name: "acr_values", params: []string{"acr_values", "urn:mace:incommon:iap:silver 1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := &browser{t: t, handler: handler}
			resp := b.signIn(b.authorize(http.MethodGet, withScope("openid profile", tt.params...)))
			if resp.status == http.StatusOK {
				resp = b.decide(resp, "allow")
			}
			if acr, ok := verify(t, handler, idToken(t, handler, resp)).claims["acr"]; ok {
				t.Errorf("ID token acr = %v, want none", acr)
			}
		})
	}
}

// REQ-CORE-24: an id_token_hint that names the End-User signed in, or
// signing in, gets a positive response. One that names another End-User
// gets login_required at once with prompt=none; otherwise it sends the
// browser to the login form, and gets login_required if the End-User who
// signs in there is not the one it names.
func TestIDTokenHint(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	// An ID token for each End-User, with each one's Consent given.
	hints := map[string]string{}
	for _, u := range []struct{ name, password string }{{"alice", alicePassword}, {"bob", bobPassword}} {
		b := &browser{t: t, handler: handler}
		resp := b.signInAs(b.authorize(http.MethodGet, authorizationParams()), u.name, u.password)
		hints[u.name] = idToken(t, handler, b.decide(resp, "allow"))
	}
	loginRequired := url.Values{"error": {"login_required"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}}

	tests := []struct {
		name   string
		hint   string // whose ID token is the hint
		prompt string
		// respond follows resp, the authorization endpoint's response to
		// alice's browser, and returns its final response.
		respond func(b *browser, resp response) response
		want    url.Values // the error response; nil for a code
	}{
		{name: "alice's, prompt=none", hint: "alice", prompt: "none", respond: func(_ *browser, resp response) response { return resp }},
		{name: "alice's", hint: "alice", respond: func(_ *browser, resp response) response { return resp }},
		{name: "bob's, prompt=none", hint: "bob", prompt: "none", respond: func(_ *browser, resp response) response { return resp }, want: loginRequired},
		{name: "bob's, alice signs in again", hint: "bob", respond: (*browser).reauthenticate, want: loginRequired},
		{
			name: "bob's, bob signs in", hint: "bob",
			respond: func(b *browser, resp response) response {
				if u := location(b.t, resp); u.Path != loginPath {
					b.t.Fatalf("redirected to %q, want the login page %q", u, loginPath)
				}
				return b.signInAs(resp, "bob", bobPassword)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := &browser{t: t, handler: handler}
			wantCode(t, b.signIn(b.authorize(http.MethodGet, authorizationParams())), "alice's request")
			resp := tt.respond(b, b.authorize(http.MethodGet, withScope("openid profile", "id_token_hint", hints[tt.hint], "prompt", tt.prompt)))
			if tt.want == nil {
				wantCode(t, resp, tt.name)
				return
			}
			if diff := cmp.Diff(tt.want, errorResponse(t, resp)); diff != "" {
				t.Errorf("%s: error response mismatch (-want +got):\n%s", tt.name, diff)
			}
		})
	}
}

// REQ-CORE-24: an id_token_hint that is not an ID token this OP issued is
// invalid_request.
func TestIDTokenHintInvalid(t *testing.T) {
	t.Parallel()

	handler := newFlowHandlerWithoutDatabase(t)
	enc := base64.RawURLEncoding.EncodeToString
	header := enc([]byte(`{"alg":"RS256"}`))
	tests := []struct {
		name string
		hint string
	}{
		{name: "not a JWT", hint: "not-a-jwt"},
		{name: "another issuer", hint: header + "." + enc([]byte(`{"iss":"https://other.example","sub":"`+aliceSubject+`"}`)) + "." + enc([]byte("sig"))},
		{name: "no sub", hint: header + "." + enc([]byte(`{"iss":"`+loginIssuer+`"}`)) + "." + enc([]byte("sig"))},
		{name: "alg none", hint: enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(`{"iss":"`+loginIssuer+`","sub":"`+aliceSubject+`"}`)) + "."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := &browser{t: t, handler: handler}
			resp := b.authorize(http.MethodGet, withScope("openid", "id_token_hint", tt.hint))
			want := url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}}
			if diff := cmp.Diff(want, errorResponse(t, resp)); diff != "" {
				t.Errorf("id_token_hint %s: error response mismatch (-want +got):\n%s", tt.name, diff)
			}
		})
	}
}

// REQ-CORE-18, REQ-CORE-19: prompt=none with any other value is
// invalid_request; a prompt value pulsar does not know is ignored.
func TestPromptValues(t *testing.T) {
	t.Parallel()

	handler := newFlowHandlerWithoutDatabase(t)
	tests := []struct {
		prompt string
		want   url.Values // the error response; nil for the login page
	}{
		{prompt: "none login", want: url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}}},
		{prompt: "consent none", want: url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}}},
		{prompt: "none select_account", want: url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}}},
		{prompt: "none x-unknown", want: url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}}},
		{prompt: "x-unknown"},
		{prompt: "create"},
		{prompt: "login x-unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.prompt, func(t *testing.T) {
			t.Parallel()
			params := authorizationParams()
			params.Set("prompt", tt.prompt)
			b := &browser{t: t, handler: handler}
			resp := b.authorize(http.MethodGet, params)
			if tt.want == nil {
				if u := location(t, resp); u.Path != loginPath {
					t.Errorf("prompt=%q redirected to %q, want the login page %q", tt.prompt, u, loginPath)
				}
				return
			}
			if diff := cmp.Diff(tt.want, errorResponse(t, resp)); diff != "" {
				t.Errorf("prompt=%q error response mismatch (-want +got):\n%s", tt.prompt, diff)
			}
		})
	}
}
