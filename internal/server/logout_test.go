package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"html"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palebluedot4/pulsar/internal/config"
	"github.com/palebluedot4/pulsar/internal/guessing"
	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
	"github.com/palebluedot4/pulsar/internal/signing"
)

// logoutPath is the path of the logout endpoint under loginIssuer.
const logoutPath = "/tenant/logout"

// The post-logout redirect URIs flowRegistry registers: two for rp, one
// with a query, and one for other.
const (
	rpSignedOutURI      = "https://rp.example/signed-out"
	rpQuerySignedOutURI = "https://rp.example/bye?tenant=a"
	otherSignedOutURI   = "https://other.example/signed-out"
)

// longState is a state of 128 characters, as the conformance suite sends,
// with characters that a URL must escape, to show that it comes back
// unchanged.
var longState = strings.Repeat("a/b+c=d&e~", 12) + "f g%h?i#"

// What the logout pages show, as their templates write them. The
// confirmation page's Client, form and hidden fields are written as the
// consent page's are, and read with consentClient, consentAction and
// consentHidden.
var (
	logoutSignedIn = regexp.MustCompile(`<p id="signed-in">Signed in as ([^<]*)\.</p>`)
	logoutOutcome  = regexp.MustCompile(`<p id="outcome">([^<]*)</p>`)
)

// What the pages that end a logout without a redirect say, and the title
// of the error page.
const (
	signedOut      = "You are signed out."
	stillSignedIn  = "You are still signed in."
	errorPageTitle = "Invalid request"
)

// The answers the confirmation form submits.
const (
	confirmLogout = "logout"
	declineLogout = "stay"
)

// logoutConfirmationPath is where the confirmation form is submitted,
// under loginIssuer.
const logoutConfirmationPath = "/tenant/logout/confirm"

// pageHeaders are the headers of every page pulsar serves.
var pageHeaders = map[string]string{
	"Content-Type":            "text/html; charset=utf-8",
	"Cache-Control":           "no-store",
	"X-Frame-Options":         "DENY",
	"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}

// logoutPage is a logout confirmation page: the Client it names, if any,
// the End-User it says is signed in, if any, the URL its form is
// submitted to, and the hidden fields the form submits.
type logoutPage struct {
	client   string
	signedIn string
	action   *url.URL
	hidden   url.Values
}

// parseLogoutPage returns the confirmation page that resp shows, failing
// the test if it shows none.
func parseLogoutPage(t *testing.T, resp response) logoutPage {
	t.Helper()
	if resp.status != http.StatusOK {
		t.Fatalf("status = %d, want %d and the logout confirmation page; Location %q, body %q", resp.status, http.StatusOK, resp.header.Get("Location"), resp.body)
	}
	action := consentAction.FindStringSubmatch(resp.body)
	if action == nil {
		t.Fatalf("body = %q, want the logout confirmation page", resp.body)
	}
	u, err := url.Parse(html.UnescapeString(action[1]))
	if err != nil {
		t.Fatalf("logout form action %q is not a URL: %v", action[1], err)
	}
	page := logoutPage{action: u, hidden: url.Values{}}
	if m := consentClient.FindStringSubmatch(resp.body); m != nil {
		page.client = html.UnescapeString(m[1])
	}
	if m := logoutSignedIn.FindStringSubmatch(resp.body); m != nil {
		page.signedIn = html.UnescapeString(m[1])
	}
	for _, m := range consentHidden.FindAllStringSubmatch(resp.body, -1) {
		page.hidden.Add(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
	}
	return page
}

// outcome returns what the page resp shows says of the logout, failing the
// test if resp is not such a page.
func outcome(t *testing.T, resp response) string {
	t.Helper()
	if resp.status != http.StatusOK {
		t.Fatalf("status = %d, want %d and a page; Location %q", resp.status, http.StatusOK, resp.header.Get("Location"))
	}
	m := logoutOutcome.FindStringSubmatch(resp.body)
	if m == nil {
		t.Fatalf("body = %q, want a page that says whether the End-User is signed out", resp.body)
	}
	return m[1]
}

// logout sends the browser to the logout endpoint with params, by method,
// as a Client does. A POST comes from a form on the Client's site, so the
// browser leaves out the SameSite=Lax Login Session cookie.
func (b *browser) logout(method string, params url.Values) response {
	b.t.Helper()
	if method != http.MethodPost {
		return b.send(method, logoutPath+"?"+params.Encode(), nil)
	}
	req := newFormRequest(b.t, logoutPath, params)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Origin", "https://rp.example")
	return (&browser{t: b.t, handler: b.handler}).do(req)
}

// confirmationForm returns the body of a confirmation form submitted
// directly, rather than from the page: params, the decision, and the
// Subject of the End-User the page would have been shown for.
func confirmationForm(params url.Values, decision, endUser string) url.Values {
	form := url.Values{"decision": {decision}, "end_user": {endUser}}
	maps.Copy(form, params)
	return form
}

// answerLogout submits the form of the confirmation page resp shows with
// decision, and returns the response.
func (b *browser) answerLogout(resp response, decision string) response {
	b.t.Helper()
	page := parseLogoutPage(b.t, resp)
	form := url.Values{"decision": {decision}}
	maps.Copy(form, page.hidden)
	return b.do(newFormRequest(b.t, page.action.RequestURI(), form))
}

// newFormRequest returns a POST of form to target, a path with any query,
// on the OP's origin.
func newFormRequest(t *testing.T, target string, form url.Values) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://op.example"+target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// signedInWithHint signs a new browser in as alice through an authorization
// request from rp, and returns the browser and the ID token rp received.
func signedInWithHint(t *testing.T, handler http.Handler) (*browser, string) {
	t.Helper()
	b := &browser{t: t, handler: handler}
	resp := b.signIn(b.authorize(http.MethodGet, authorizationParams()))
	if resp.status == http.StatusOK {
		resp = b.decide(resp, "allow")
	}
	return b, idToken(t, handler, resp)
}

// wantSignedOut checks that the browser with the Login Session cookie
// session is signed in no longer: an authorization request with
// prompt=none gets login_required.
func wantSignedOut(t *testing.T, handler http.Handler, session *http.Cookie, when string) {
	t.Helper()
	b := &browser{t: t, handler: handler, session: session}
	resp := b.authorize(http.MethodGet, requestWith(url.Values{"prompt": {"none"}}))
	want := url.Values{"error": {"login_required"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}}
	if diff := cmp.Diff(want, errorResponse(t, resp)); diff != "" {
		t.Errorf("%s: prompt=none response mismatch (-want +got):\n%s", when, diff)
	}
}

// wantSignedIn checks that the browser b is still signed in: an
// authorization request with prompt=none gets a code.
func wantSignedIn(t *testing.T, b *browser, when string) {
	t.Helper()
	wantCode(t, b.authorize(http.MethodGet, requestWith(url.Values{"prompt": {"none"}})), when)
}

// REQ-LOGOUT-1, REQ-LOGOUT-2, REQ-LOGOUT-5, REQ-LOGOUT-6, REQ-LOGOUT-8,
// REQ-BCP-2: a Client sends the signed-in End-User to the logout endpoint,
// by GET or POST, with the ID token it received, a post-logout redirect
// URI it registered and a state. pulsar asks the End-User to confirm, on a
// page that names the Client and may not be framed, and that names the
// End-User too when the request carries the Login Session cookie, as a
// cross-site POST does not. Confirming ends the Login Session and clears
// its cookie, and returns the End-User to the URI with the state,
// unchanged, and nothing else. prompt=none then gets login_required,
// whether the browser sends the cleared cookie or the old one. No URL
// pulsar sends the browser to, or submits its form to, carries the hint.
func TestLogout(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	tests := []struct {
		method       string
		redirectURI  string
		wantSignedIn string // the End-User the page names
		want         string // where confirming sends the browser
	}{
		{method: http.MethodGet, redirectURI: rpSignedOutURI, wantSignedIn: "alice", want: rpSignedOutURI + "?" + url.Values{"state": {longState}}.Encode()},
		{method: http.MethodPost, redirectURI: rpSignedOutURI, want: rpSignedOutURI + "?" + url.Values{"state": {longState}}.Encode()},
		{method: http.MethodGet, redirectURI: rpQuerySignedOutURI, wantSignedIn: "alice", want: rpQuerySignedOutURI + "&" + url.Values{"state": {longState}}.Encode()},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.redirectURI, func(t *testing.T) {
			t.Parallel()
			b, hint := signedInWithHint(t, handler)
			old := b.session
			resp := b.logout(tt.method, url.Values{
				"id_token_hint":            {hint},
				"post_logout_redirect_uri": {tt.redirectURI},
				"state":                    {longState},
			})
			page := parseLogoutPage(t, resp)
			type shown struct{ Client, SignedIn string }
			if diff := cmp.Diff(shown{Client: "rp", SignedIn: tt.wantSignedIn}, shown{Client: page.client, SignedIn: page.signedIn}); diff != "" {
				t.Errorf("logout confirmation page mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(pageHeaders, headers(resp.header, pageHeaders)); diff != "" {
				t.Errorf("logout confirmation page headers mismatch (-want +got):\n%s", diff)
			}
			if got := page.action.String(); got != logoutConfirmationPath {
				t.Errorf("logout confirmation form action = %q, want %q, with the request in the body", got, logoutConfirmationPath)
			}

			resp = b.answerLogout(resp, confirmLogout)
			if got := location(t, resp).String(); got != tt.want {
				t.Errorf("confirmed logout redirects to %q, want %q", got, tt.want)
			}
			if strings.Contains(resp.header.Get("Location"), hint) {
				t.Errorf("confirmed logout redirect %q carries the id_token_hint", resp.header.Get("Location"))
			}
			if got := resp.header.Get("Cache-Control"); got != "no-store" {
				t.Errorf("confirmed logout Cache-Control = %q, want %q", got, "no-store")
			}
			if b.session == nil || b.session.MaxAge >= 0 || b.session.Value != "" {
				t.Errorf("confirmed logout Login Session cookie = %v, want it cleared", b.session)
			}
			wantSignedOut(t, handler, b.session, "with the cleared cookie")
			wantSignedOut(t, handler, old, "with the old cookie")
		})
	}
}

// wantErrorPage checks that resp is the error page, which redirects
// nowhere.
func wantErrorPage(t *testing.T, resp response, when string) {
	t.Helper()
	if resp.status != http.StatusBadRequest || !strings.Contains(resp.body, "<h1>"+errorPageTitle+"</h1>") {
		t.Errorf("%s: status = %d, Location %q, body %q; want %d and the error page", when, resp.status, resp.header.Get("Location"), resp.body, http.StatusBadRequest)
	}
	if diff := cmp.Diff(pageHeaders, headers(resp.header, pageHeaders)); diff != "" {
		t.Errorf("%s: error page headers mismatch (-want +got):\n%s", when, diff)
	}
}

// REQ-LOGOUT-2, REQ-LOGOUT-12: an id_token_hint that is not an ID token
// this OP issued to a registered Client, signed by RS256 with one of its
// keys, with its own issuer, gets an error page, with no
// confirmation, no redirect and no logout, whether it is sent to the
// logout endpoint or with a confirmation submitted directly.
func TestLogoutInvalidHint(t *testing.T) {
	t.Parallel()

	pool := postgrestest.Open(t, postgrestest.NewDatabase(t))
	handler := newFlowHandler(t, pool)
	keys := forger(t, pool)
	signedIn, hint := signedInWithHint(t, handler)
	valid := verify(t, handler, hint)
	with := func(name string, value any) map[string]any {
		c := maps.Clone(valid.claims)
		if value == nil {
			delete(c, name)
		} else {
			c[name] = value
		}
		return c
	}
	parts := strings.Split(hint, ".")
	enc := base64.RawURLEncoding.EncodeToString
	other := jwtKey(jose.RS256)
	hmacKey := []byte(strings.Repeat(rpSecret, 2)) // rp's secret, long enough for HS256
	tests := []struct {
		name string
		hint string
	}{
		{name: "alg none, signature dropped", hint: enc([]byte(`{"alg":"none"}`)) + "." + parts[1] + "."},
		{name: "HS256 keyed with rp's secret", hint: signAssertion(t, jose.HS256, hmacKey, valid.kid, valid.claims)},
		{name: "signed by another key under the OP's kid", hint: signAssertion(t, other.alg, other.key, valid.kid, valid.claims)},
		{name: "claims changed after signing", hint: parts[0] + "." + enc([]byte(`{"iss":"`+loginIssuer+`","aud":"other","sub":"`+aliceSubject+`"}`)) + "." + parts[2]},
		{name: "another issuer", hint: forge(t, keys, "JWT", with("iss", "https://other.example"))},
		{name: "no issuer", hint: forge(t, keys, "JWT", with("iss", nil))},
		{name: "aud of no registered Client", hint: forge(t, keys, "JWT", with("aud", "unknown"))},
		{name: "two audiences", hint: forge(t, keys, "JWT", with("aud", []string{"rp", "other"}))},
		{name: "no aud", hint: forge(t, keys, "JWT", with("aud", nil))},
		{name: "typ of an access token", hint: forge(t, keys, "at+jwt", valid.claims)},
		{name: "not a JWT", hint: "not-a-jwt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := &browser{t: t, handler: handler, session: signedIn.session}
			params := url.Values{"id_token_hint": {tt.hint}, "post_logout_redirect_uri": {rpSignedOutURI}, "state": {"xyz"}}
			wantErrorPage(t, b.logout(http.MethodGet, params), "logout request")

			form := confirmationForm(params, confirmLogout, aliceSubject)
			wantErrorPage(t, b.do(newFormRequest(t, logoutConfirmationPath, form)), "confirmation submitted directly")
			wantSignedIn(t, b, "after an invalid id_token_hint")
		})
	}
}

// REQ-LOGOUT-4, REQ-LOGOUT-12: a client_id that is not the Client the
// id_token_hint was issued to, whether another registered Client or none,
// gets the error page, by GET or POST, and with a confirmation submitted
// directly: no confirmation, no redirect, and the End-User stays signed in.
func TestLogoutClientIDDisagreesWithHint(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	signedIn, hint := signedInWithHint(t, handler)
	tests := []struct {
		name     string
		method   string
		clientID string
		uri      string
	}{
		{name: "GET, another Client with its URI", method: http.MethodGet, clientID: "other", uri: otherSignedOutURI},
		{name: "GET, another Client with the hint's Client's URI", method: http.MethodGet, clientID: "other", uri: rpSignedOutURI},
		{name: "POST, another Client with its URI", method: http.MethodPost, clientID: "other", uri: otherSignedOutURI},
		{name: "GET, no registered Client", method: http.MethodGet, clientID: "unknown", uri: rpSignedOutURI},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := &browser{t: t, handler: handler, session: signedIn.session}
			params := url.Values{"id_token_hint": {hint}, "client_id": {tt.clientID}, "post_logout_redirect_uri": {tt.uri}, "state": {"xyz"}}
			wantErrorPage(t, b.logout(tt.method, params), "logout request")

			form := confirmationForm(params, confirmLogout, aliceSubject)
			wantErrorPage(t, b.do(newFormRequest(t, logoutConfirmationPath, form)), "confirmation submitted directly")
			wantSignedIn(t, b, "after a client_id that disagrees with the hint")
		})
	}
}

// REQ-LOGOUT-4, REQ-LOGOUT-5, REQ-LOGOUT-7, REQ-LOGOUT-9, REQ-LOGOUT-12,
// REQ-LOGOUT-13: pulsar returns the End-User to a post-logout redirect URI
// only when the request identifies the Client, by its id_token_hint or its
// client_id, or both when they agree, and the URI is exactly one that
// Client registered. Otherwise it asks the End-User to confirm all the
// same, naming the Client only if it is identified, and then shows that
// they are signed out. logout_hint and ui_locales change nothing.
func TestLogoutRedirectOnlyToRegisteredURI(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	withState := func(uri string) string { return uri + "?state=xyz" }
	tests := []struct {
		name string
		// params are the request's parameters; "HINT" stands for the ID
		// token rp received for the End-User.
		params     url.Values
		wantClient string // the Client the page names, if any
		want       string // where confirming sends the browser; "" for the signed-out page
	}{
		{
			name:       "hint and client_id that agree",
			params:     url.Values{"id_token_hint": {"HINT"}, "client_id": {"rp"}, "post_logout_redirect_uri": {rpSignedOutURI}, "state": {"xyz"}},
			wantClient: "rp", want: withState(rpSignedOutURI),
		},
		{
			name:       "client_id alone",
			params:     url.Values{"client_id": {"rp"}, "post_logout_redirect_uri": {rpSignedOutURI}, "state": {"xyz"}},
			wantClient: "rp", want: withState(rpSignedOutURI),
		},
		{
			name:       "no state",
			params:     url.Values{"id_token_hint": {"HINT"}, "post_logout_redirect_uri": {rpSignedOutURI}},
			wantClient: "rp", want: rpSignedOutURI,
		},
		{
			name:       "logout_hint and ui_locales",
			params:     url.Values{"id_token_hint": {"HINT"}, "post_logout_redirect_uri": {rpSignedOutURI}, "state": {"xyz"}, "logout_hint": {"alice"}, "ui_locales": {"tlh fr-CA"}},
			wantClient: "rp", want: withState(rpSignedOutURI),
		},
		{
			name:       "unregistered URI",
			params:     url.Values{"id_token_hint": {"HINT"}, "post_logout_redirect_uri": {"https://attacker.example/"}, "state": {"xyz"}},
			wantClient: "rp",
		},
		{
			name:       "registered URI with a query added",
			params:     url.Values{"id_token_hint": {"HINT"}, "post_logout_redirect_uri": {rpSignedOutURI + "?foo=bar"}, "state": {"xyz"}},
			wantClient: "rp",
		},
		{
			name:       "registered URI with a trailing slash",
			params:     url.Values{"id_token_hint": {"HINT"}, "post_logout_redirect_uri": {rpSignedOutURI + "/"}, "state": {"xyz"}},
			wantClient: "rp",
		},
		{
			name:       "registered URI in another case",
			params:     url.Values{"id_token_hint": {"HINT"}, "post_logout_redirect_uri": {"https://RP.example/signed-out"}, "state": {"xyz"}},
			wantClient: "rp",
		},
		{
			name:       "redirect URI rather than post-logout redirect URI",
			params:     url.Values{"id_token_hint": {"HINT"}, "post_logout_redirect_uri": {rpRedirectURI}, "state": {"xyz"}},
			wantClient: "rp",
		},
		{
			name:       "URI another Client registered",
			params:     url.Values{"id_token_hint": {"HINT"}, "post_logout_redirect_uri": {otherSignedOutURI}, "state": {"xyz"}},
			wantClient: "rp",
		},
		{
			name:   "no hint and no client_id",
			params: url.Values{"post_logout_redirect_uri": {rpSignedOutURI}, "state": {"xyz"}},
		},
		{
			name:   "client_id of no registered Client",
			params: url.Values{"client_id": {"unknown"}, "post_logout_redirect_uri": {rpSignedOutURI}, "state": {"xyz"}},
		},
		{
			name:       "client_id of a Client that registered none",
			params:     url.Values{"client_id": {"public"}, "post_logout_redirect_uri": {rpSignedOutURI}, "state": {"xyz"}},
			wantClient: "public",
		},
		{
			name:       "hint alone",
			params:     url.Values{"id_token_hint": {"HINT"}, "state": {"xyz"}},
			wantClient: "rp",
		},
		{name: "state alone", params: url.Values{"state": {"xyz"}}},
		{name: "no parameters", params: url.Values{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, hint := signedInWithHint(t, handler)
			params := url.Values{}
			for k, vs := range tt.params {
				for _, v := range vs {
					params.Add(k, strings.ReplaceAll(v, "HINT", hint))
				}
			}
			resp := b.logout(http.MethodGet, params)
			if got := parseLogoutPage(t, resp).client; got != tt.wantClient {
				t.Errorf("logout confirmation page names the client %q, want %q", got, tt.wantClient)
			}
			resp = b.answerLogout(resp, confirmLogout)
			if tt.want != "" {
				if got := location(t, resp).String(); got != tt.want {
					t.Errorf("confirmed logout redirects to %q, want %q", got, tt.want)
				}
			} else {
				if got := outcome(t, resp); got != signedOut {
					t.Errorf("confirmed logout page says %q, want %q", got, signedOut)
				}
				if diff := cmp.Diff(pageHeaders, headers(resp.header, pageHeaders)); diff != "" {
					t.Errorf("signed-out page headers mismatch (-want +got):\n%s", diff)
				}
			}
			wantSignedOut(t, handler, b.session, "after the logout")
		})
	}
}

// REQ-LOGOUT-8: an End-User who declines stays signed in, and is returned
// to the Client as a confirmed logout would return them, or shown that
// they are still signed in.
func TestLogoutDeclined(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	tests := []struct {
		name        string
		redirectURI string
		want        string // where declining sends the browser; "" for the page
	}{
		{name: "registered URI", redirectURI: rpSignedOutURI, want: rpSignedOutURI + "?state=xyz"},
		{name: "unregistered URI", redirectURI: "https://attacker.example/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, hint := signedInWithHint(t, handler)
			resp := b.logout(http.MethodGet, url.Values{"id_token_hint": {hint}, "post_logout_redirect_uri": {tt.redirectURI}, "state": {"xyz"}})
			resp = b.answerLogout(resp, declineLogout)
			if tt.want != "" {
				if got := location(t, resp).String(); got != tt.want {
					t.Errorf("declined logout redirects to %q, want %q", got, tt.want)
				}
			} else if got := outcome(t, resp); got != stillSignedIn {
				t.Errorf("declined logout page says %q, want %q", got, stillSignedIn)
			}
			wantSignedIn(t, b, "after declining")
		})
	}
}

// REQ-LOGOUT-11: a browser without a Login Session can be sent to the
// logout endpoint, as with one: it is asked to confirm, with no End-User
// named, and then returned to the Client or shown that it is signed out,
// whichever it answers, since it is.
func TestLogoutWithoutLoginSession(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	_, hint := signedInWithHint(t, handler)
	withURI := url.Values{"id_token_hint": {hint}, "post_logout_redirect_uri": {rpSignedOutURI}, "state": {"xyz"}}
	tests := []struct {
		name     string
		params   url.Values
		decision string
		want     string // where answering sends the browser; "" for the signed-out page
	}{
		{name: "hint and registered URI, confirmed", params: withURI, decision: confirmLogout, want: rpSignedOutURI + "?state=xyz"},
		{name: "hint and registered URI, declined", params: withURI, decision: declineLogout, want: rpSignedOutURI + "?state=xyz"},
		{name: "no parameters, confirmed", params: url.Values{}, decision: confirmLogout},
		{name: "no parameters, declined", params: url.Values{}, decision: declineLogout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := &browser{t: t, handler: handler}
			resp := b.logout(http.MethodGet, tt.params)
			if got := parseLogoutPage(t, resp).signedIn; got != "" {
				t.Errorf("logout confirmation page says the browser is signed in as %q, want no one", got)
			}
			resp = b.answerLogout(resp, tt.decision)
			if tt.want != "" {
				if got := location(t, resp).String(); got != tt.want {
					t.Errorf("answered logout redirects to %q, want %q", got, tt.want)
				}
			} else if got := outcome(t, resp); got != signedOut {
				t.Errorf("answered logout page says %q, want %q", got, signedOut)
			}
		})
	}
}

// REQ-LOGOUT-11: a Login Session that ends while the confirmation page is
// open, after 30 minutes idle, has already logged the End-User out, so
// their answer finishes the logout: they are returned to the Client, not
// asked again.
func TestLogoutLoginSessionEndedWhilePageOpen(t *testing.T) {
	t.Parallel()

	databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
	synctest.Test(t, func(t *testing.T) {
		handler := newBubbleFlowHandler(t, databaseURL)
		b, hint := signedInWithHint(t, handler)
		resp := b.logout(http.MethodGet, url.Values{"id_token_hint": {hint}, "post_logout_redirect_uri": {rpSignedOutURI}, "state": {"xyz"}})
		if got := parseLogoutPage(t, resp).signedIn; got != "alice" {
			t.Fatalf("logout confirmation page names %q, want alice", got)
		}
		time.Sleep(31 * time.Minute)
		resp = b.answerLogout(resp, confirmLogout)
		if got, want := location(t, resp).String(), rpSignedOutURI+"?state=xyz"; got != want {
			t.Errorf("logout confirmed after the Login Session ended redirects to %q, want %q", got, want)
		}
	})
}

// REQ-LOGOUT-13, REQ-LOGOUT-8: only the End-User's own confirmation, made
// in their browser, ends their Login Session. A cross-origin submission is
// refused and a submission without an answer is malformed. One made on a
// page shown for another End-User, or for no one, is not counted, and
// the End-User signed in now is asked again, by name. Each leaves the
// End-User signed in.
func TestLogoutConfirmationCannotBeForged(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	params := url.Values{"client_id": {"rp"}, "post_logout_redirect_uri": {rpSignedOutURI}, "state": {"xyz"}}
	tests := []struct {
		name         string
		form         url.Values
		header       http.Header
		wantStatus   int
		wantAskAgain bool // whether the response is the confirmation page, naming alice
	}{
		{
			name:       "cross-origin submission",
			form:       confirmationForm(params, confirmLogout, aliceSubject),
			header:     http.Header{"Sec-Fetch-Site": {"cross-site"}},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "submission from another origin without Sec-Fetch-Site",
			form:       confirmationForm(params, confirmLogout, aliceSubject),
			header:     http.Header{"Origin": {"https://attacker.example"}},
			wantStatus: http.StatusForbidden,
		},
		{name: "no answer", form: confirmationForm(params, "", aliceSubject), wantStatus: http.StatusBadRequest},
		{name: "unknown answer", form: confirmationForm(params, "yes", aliceSubject), wantStatus: http.StatusBadRequest},
		{
			name:       "shown for another End-User",
			form:       confirmationForm(params, confirmLogout, bobSubject),
			wantStatus: http.StatusOK, wantAskAgain: true,
		},
		{
			name:       "shown with no one signed in",
			form:       confirmationForm(params, confirmLogout, ""),
			wantStatus: http.StatusOK, wantAskAgain: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, _ := signedInWithHint(t, handler)
			req := newFormRequest(t, logoutConfirmationPath, tt.form)
			maps.Copy(req.Header, tt.header)
			resp := b.do(req)
			if resp.status != tt.wantStatus {
				t.Errorf("POST %s status = %d, want %d; Location %q", logoutConfirmationPath, resp.status, tt.wantStatus, resp.header.Get("Location"))
			}
			if tt.wantAskAgain {
				if got := parseLogoutPage(t, resp).signedIn; got != "alice" {
					t.Errorf("POST %s asks again for %q, want alice", logoutConfirmationPath, got)
				}
			}
			wantSignedIn(t, b, "after "+tt.name)
		})
	}
}

// REQ-LOGOUT-12: a logout request that repeats a parameter pulsar reads,
// or that it cannot read, gets the error page and logs no one out.
func TestLogoutMalformedRequest(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	signedIn, hint := signedInWithHint(t, handler)
	for _, name := range []string{"id_token_hint", "client_id", "post_logout_redirect_uri", "state"} {
		t.Run("repeated "+name, func(t *testing.T) {
			t.Parallel()
			b := &browser{t: t, handler: handler, session: signedIn.session}
			params := url.Values{"id_token_hint": {hint}, "client_id": {"rp"}, "post_logout_redirect_uri": {rpSignedOutURI}, "state": {"xyz"}}
			params.Add(name, params.Get(name))
			wantErrorPage(t, b.logout(http.MethodGet, params), "logout request")
			wantSignedIn(t, b, "after a malformed request")
		})
	}
	t.Run("POST not form-encoded", func(t *testing.T) {
		t.Parallel()
		b := &browser{t: t, handler: handler, session: signedIn.session}
		req := newFormRequest(t, logoutPath, url.Values{"id_token_hint": {hint}})
		req.Header.Set("Content-Type", "application/json")
		wantErrorPage(t, b.do(req), "logout request")
		wantSignedIn(t, b, "after a malformed request")
	})
}

// REQ-LOGOUT-3: an id_token_hint whose exp has passed is accepted. The
// End-User returns an hour after signing in, still within their Login
// Session; the hint still identifies the Client, which gets them back.
func TestLogoutExpiredHint(t *testing.T) {
	t.Parallel()

	databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
	synctest.Test(t, func(t *testing.T) {
		handler := newBubbleFlowHandler(t, databaseURL)
		b, hint := signedInWithHint(t, handler)
		exp, _ := verify(t, handler, hint).claims["exp"].(float64)

		// Within the Login Session's limits: idle for 20 minutes at a time,
		// under its 30, and an hour in all, under its 10.
		for range 3 {
			time.Sleep(20 * time.Minute)
			wantSignedIn(t, b, "while waiting")
		}
		if now := float64(time.Now().Unix()); now < exp {
			t.Fatalf("now = %v, want past the hint's exp %v", now, exp)
		}

		resp := b.logout(http.MethodGet, url.Values{"id_token_hint": {hint}, "post_logout_redirect_uri": {rpSignedOutURI}, "state": {"xyz"}})
		resp = b.answerLogout(resp, confirmLogout)
		if got, want := location(t, resp).String(), rpSignedOutURI+"?state=xyz"; got != want {
			t.Errorf("confirmed logout with an expired hint redirects to %q, want %q", got, want)
		}
		wantSignedOut(t, handler, b.session, "after the logout")
	})
}

// REQ-BCP-13: logout ends the Login Session and nothing else. The refresh
// token a confidential or a public Client holds for offline access still
// refreshes, and the access token issued with it is still accepted at
// UserInfo until it expires.
func TestLogoutKeepsTokens(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
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
			c := tt.client
			params := clientParams(c.clientID, c.redirectURI)
			params.Set("scope", "openid email offline_access")
			params.Set("prompt", "consent")
			if c.challenge != "" {
				withChallenge(params, c.challenge)
			}
			b := &browser{t: t, handler: handler}
			code := location(t, b.decide(b.signIn(b.authorize(http.MethodGet, params)), "allow")).Query().Get("code")
			tokens := tokenResponseOf(t, c.redeem(t, handler, c.form(code, tt.verifier)))

			resp := b.logout(http.MethodGet, url.Values{"id_token_hint": {tokens.IDToken}})
			if got := outcome(t, b.answerLogout(resp, confirmLogout)); got != signedOut {
				t.Fatalf("confirmed logout page says %q, want %q", got, signedOut)
			}
			wantSignedOut(t, handler, b.session, "after the logout")

			if diff := cmp.Diff(claimsOf(aliceEmail), userInfoClaims(t, userInfo(t, handler, getHeader, tokens.AccessToken))); diff != "" {
				t.Errorf("UserInfo claims after logout mismatch (-want +got):\n%s", diff)
			}
			if r := tokenResponseOf(t, c.refresh(t, handler, tokens.RefreshToken, "")); r.RefreshToken == "" {
				t.Errorf("refresh after logout issued no refresh_token")
			}
		})
	}
}

// newReloadingBubbleFlowHandler returns the handler of newBubbleFlowHandler,
// whose signing keys reload every interval until the test ends, as a
// serving replica's do, and the pool behind it.
func newReloadingBubbleFlowHandler(t *testing.T, databaseURL string) (http.Handler, *pgxpool.Pool) {
	t.Helper()
	pool := newBubblePool(t, databaseURL)
	keys := signing.New(pool, config.Secret{})
	if err := keys.Load(t.Context()); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	logger := slog.New(slog.NewTextHandler(t.Output(), nil))
	ctx, cancel := context.WithCancel(t.Context())
	reloading := make(chan struct{})
	go func() {
		defer close(reloading)
		keys.Run(ctx, logger)
	}()
	t.Cleanup(func() {
		cancel()
		<-reloading
	})
	return New(logger, mustParse(t, loginIssuer), pool, keys, flowRegistry(t), guessing.New(pool, nil), ready()), pool
}

// publishedKids returns the kids of the JWK Set the handler serves, sorted.
func publishedKids(t *testing.T, handler http.Handler) []string {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://op.example"+jwksPath, http.NoBody))
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatalf("GET %s body is not a JWK Set: %v", jwksPath, err)
	}
	var kids []string
	for _, k := range set.Keys {
		kids = append(kids, k.KeyID)
	}
	slices.Sort(kids)
	return kids
}

// sleepUntil sleeps until t, by the bubble's clock, and waits for the
// bubble's goroutines to block.
func sleepUntil(t time.Time) {
	time.Sleep(time.Until(t))
	synctest.Wait()
}

// REQ-LOGOUT-2, REQ-LOGOUT-3: after `pulsar keys rotate`, an ID token the
// replaced key signed is still accepted as an id_token_hint while a Login
// Session in which that key signed could last: until the Login Session's
// ten-hour lifetime, plus a reload interval, has passed since the new key
// started signing. From then on it gets the error page. Throughout, the
// replaced key is gone from the JWK Set from eleven minutes after the new
// key started signing (REQ-CORE-51), and signs nothing.
//
// The End-User signs in before the rotation and stays active until their
// Login Session nearly ends, then logs out with the hint they got first.
func TestLogoutHintSignedByRetiredKey(t *testing.T) {
	t.Parallel()

	databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
	synctest.Test(t, func(t *testing.T) {
		handler, pool := newReloadingBubbleFlowHandler(t, databaseURL)
		b, hint := signedInWithHint(t, handler)
		sessionEnds := time.Now().Add(10 * time.Hour)
		retired := verify(t, handler, hint).kid
		// What `pulsar keys rotate` runs.
		rotated, err := signing.New(pool, config.Secret{}).Rotate(t.Context())
		if err != nil {
			t.Fatalf("Rotate() error = %v", err)
		}

		// The new key starts signing two minutes after the rotation, and the
		// old one leaves the JWK Set eleven minutes later, at a reload.
		sleepUntil(rotated.SignsFrom.Add(12 * time.Minute))
		if diff := cmp.Diff([]string{rotated.KID}, publishedKids(t, handler)); diff != "" {
			t.Errorf("GET %s once the old key has left it kids mismatch (-want +got):\n%s", jwksPath, diff)
		}
		wantSignedIn(t, b, "once the old key has left the JWK Set")
		_, idToken := signedInWithHint(t, handler)
		if got := verify(t, handler, idToken).kid; got != rotated.KID {
			t.Errorf("ID token issued after the rotation signed with %q, want the new key %q", got, rotated.KID)
		}

		// Idle for 20 minutes at a time, under the Login Session's 30.
		for time.Until(sessionEnds) > 20*time.Minute {
			time.Sleep(20 * time.Minute)
			wantSignedIn(t, b, "while waiting")
		}
		if got := publishedKids(t, handler); slices.Contains(got, retired) {
			t.Errorf("GET %s near the Login Session's end kids = %q, want no retired key %q", jwksPath, got, retired)
		}
		params := url.Values{"id_token_hint": {hint}, "post_logout_redirect_uri": {rpSignedOutURI}, "state": {"xyz"}}
		resp := b.logout(http.MethodGet, params)
		if got := parseLogoutPage(t, resp).client; got != "rp" {
			t.Errorf("logout confirmation page for a retired key's hint names the client %q, want rp", got)
		}
		resp = b.answerLogout(resp, confirmLogout)
		if got, want := location(t, resp).String(), rpSignedOutURI+"?state=xyz"; got != want {
			t.Errorf("confirmed logout with a retired key's hint redirects to %q, want %q", got, want)
		}
		wantSignedOut(t, handler, b.session, "after the logout")

		// The Login Session's lifetime and one reload interval after the new
		// key started signing.
		refusedFrom := rotated.SignsFrom.Add(10*time.Hour + time.Minute)
		sleepUntil(refusedFrom.Add(-time.Nanosecond))
		late := &browser{t: t, handler: handler}
		if got := parseLogoutPage(t, late.logout(http.MethodGet, params)).client; got != "rp" {
			t.Errorf("logout confirmation page 1ns before a retired key's hints are refused names the client %q, want rp", got)
		}
		sleepUntil(refusedFrom)
		wantErrorPage(t, late.logout(http.MethodGet, params), "hint signed by a key retired a Login Session's lifetime ago")
		if diff := cmp.Diff([]string{rotated.KID}, publishedKids(t, handler)); diff != "" {
			t.Errorf("GET %s at the end kids mismatch (-want +got):\n%s", jwksPath, diff)
		}
	})
}
