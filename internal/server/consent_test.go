package server

import (
	"encoding/json"
	"html"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
)

// consentPath is the path the consent form is submitted to, under
// loginIssuer.
const consentPath = "/tenant/consent"

// What the consent page shows, as its template writes it.
var (
	consentClient           = regexp.MustCompile(`<strong id="client">([^<]*)</strong>`)
	consentScope            = regexp.MustCompile(`<li><code>([^<]*)</code>`)
	consentAction           = regexp.MustCompile(`<form method="post" action="([^"]*)">`)
	consentScopeDescription = regexp.MustCompile(`<li><code>([^<]*)</code>: ([^<]*)</li>`)
	consentHidden           = regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)">`)
)

// consentPage is a consent page: the Client it names, the scopes it lists,
// the URL its form is submitted to, and the hidden fields the form
// submits.
type consentPage struct {
	client string
	scopes []string
	action *url.URL
	hidden url.Values
}

// parseConsentPage returns the consent page that resp shows, failing the
// test if it shows none.
func parseConsentPage(t *testing.T, resp response) consentPage {
	t.Helper()
	if resp.status != http.StatusOK {
		t.Fatalf("status = %d, want %d and the consent page; Location %q", resp.status, http.StatusOK, resp.header.Get("Location"))
	}
	client := consentClient.FindStringSubmatch(resp.body)
	action := consentAction.FindStringSubmatch(resp.body)
	if client == nil || action == nil {
		t.Fatalf("body = %q, want the consent page", resp.body)
	}
	u, err := url.Parse(html.UnescapeString(action[1]))
	if err != nil {
		t.Fatalf("consent form action %q is not a URL: %v", action[1], err)
	}
	var scopes []string
	for _, m := range consentScope.FindAllStringSubmatch(resp.body, -1) {
		scopes = append(scopes, html.UnescapeString(m[1]))
	}
	hidden := url.Values{}
	for _, m := range consentHidden.FindAllStringSubmatch(resp.body, -1) {
		hidden.Add(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
	}
	return consentPage{client: html.UnescapeString(client[1]), scopes: scopes, action: u, hidden: hidden}
}

// decide submits the consent form of the page resp shows with decision,
// "allow" or "deny", and follows the redirect back to the authorization
// endpoint, returning its response.
func (b *browser) decide(resp response, decision string) response {
	b.t.Helper()
	page := parseConsentPage(b.t, resp)
	next := location(b.t, b.submitConsent(page, url.Values{"decision": {decision}}, nil))
	if next.Path != authorizationPath {
		b.t.Fatalf("consent form redirected to %q, want %q", next, authorizationPath)
	}
	return b.send(http.MethodGet, next.RequestURI(), nil)
}

// REQ-CORE-28, REQ-CORE-27, REQ-BCP-2: the first authorization request
// from a Client asks the End-User, on a page that names the Client and
// the scopes it asks for and that may not be framed, before a code is
// issued.
func TestConsentPage(t *testing.T) {
	t.Parallel()

	b := &browser{t: t, handler: newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))}
	params := authorizationParams()
	params.Set("scope", "openid email profile unknown")
	resp := b.signIn(b.authorize(http.MethodGet, params))
	page := parseConsentPage(t, resp)
	type shown struct {
		Client string
		Scopes []string
	}
	want := shown{Client: "rp", Scopes: []string{"openid", "email", "profile"}}
	if diff := cmp.Diff(want, shown{Client: page.client, Scopes: page.scopes}); diff != "" {
		t.Errorf("consent page mismatch (-want +got):\n%s", diff)
	}
	if page.action.Path != consentPath {
		t.Errorf("consent form action = %q, want the path %q", page.action, consentPath)
	}
	wantHeader := map[string]string{
		"Content-Type":            "text/html; charset=utf-8",
		"Cache-Control":           "no-store",
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
	}
	if diff := cmp.Diff(wantHeader, headers(resp.header, wantHeader)); diff != "" {
		t.Errorf("consent page headers mismatch (-want +got):\n%s", diff)
	}
}

// REQ-CORE-28, REQ-OAUTH-22, REQ-OAUTH-9, REQ-ISS-2: allowing the request
// on the consent page issues a code; denying it sends the Client
// access_denied with state and iss, at the registered redirect URI.
func TestConsentDecision(t *testing.T) {
	t.Parallel()

	tests := []struct {
		decision string
		want     url.Values // the response's parameters; a code is checked for presence only
	}{
		{decision: "allow", want: url.Values{"code": {"present"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}}},
		{decision: "deny", want: url.Values{"error": {"access_denied"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}}},
	}
	for _, tt := range tests {
		t.Run(tt.decision, func(t *testing.T) {
			t.Parallel()
			b := &browser{t: t, handler: newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))}
			callback := location(t, b.decide(b.signIn(b.authorize(http.MethodGet, authorizationParams())), tt.decision))
			if got := withoutQuery(callback); got != rpRedirectURI {
				t.Fatalf("decision %q redirected to %q, want %q", tt.decision, got, rpRedirectURI)
			}
			got := callback.Query()
			if got.Get("code") != "" {
				got.Set("code", "present")
			}
			got.Del("error_description")
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("decision %q response parameters mismatch (-want +got):\n%s", tt.decision, diff)
			}
		})
	}
}

// A consent form submitted without the request in its URL, or without a
// decision of allow or deny, is refused with 400.
func TestConsentFormMalformed(t *testing.T) {
	t.Parallel()

	handler := newFlowHandlerWithoutDatabase(t)
	tests := []struct {
		name   string
		target string
		form   url.Values
	}{
		{name: "no request", target: consentPath, form: url.Values{"decision": {"allow"}}},
		{name: "no decision", target: consentPath + "?" + authorizationParams().Encode()},
		{name: "unknown decision", target: consentPath + "?" + authorizationParams().Encode(), form: url.Values{"decision": {"maybe"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := &browser{t: t, handler: handler}
			if resp := b.send(http.MethodPost, tt.target, tt.form); resp.status != http.StatusBadRequest {
				t.Errorf("POST %s with %s status = %d, want %d", consentPath, tt.name, resp.status, http.StatusBadRequest)
			}
		})
	}
}

// REQ-OAUTH-23, REQ-CORE-28: a decision counts only for the End-User the
// consent page was shown for. alice's page, submitted after bob signs in
// in the same browser, gives bob no Consent; bob is shown the page for
// himself.
func TestConsentDecisionBoundToEndUser(t *testing.T) {
	t.Parallel()

	b := &browser{t: t, handler: newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))}
	alicePage := parseConsentPage(t, b.signIn(b.authorize(http.MethodGet, authorizationParams())))
	b.login("bob", bobPassword, nil)

	next := location(t, b.submitConsent(alicePage, url.Values{"decision": {"allow"}}, nil))
	resp := b.send(http.MethodGet, next.RequestURI(), nil)
	parseConsentPage(t, resp)
	if !strings.Contains(resp.body, "Signed in as bob.") {
		t.Errorf("consent page after alice's page was allowed while bob is signed in = %q, want bob's", resp.body)
	}
}

// REQ-CORE-16, REQ-CORE-28: a decision on the consent page counts for 10
// minutes. Past that, the request it was made for, sent again with
// prompt=consent, shows the page again.
func TestConsentDecisionExpires(t *testing.T) {
	t.Parallel()

	databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
	synctest.Test(t, func(t *testing.T) {
		b := &browser{t: t, handler: newBubbleFlowHandler(t, databaseURL)}
		wantCode(t, b.decide(b.signIn(b.authorize(http.MethodGet, authorizationParams())), "allow"), "first request")

		params := requestWith(url.Values{"prompt": {"consent"}})
		page := parseConsentPage(t, b.authorize(http.MethodGet, params))
		b.submitConsent(page, url.Values{"decision": {"allow"}}, nil)
		time.Sleep(10 * time.Minute)
		parseConsentPage(t, b.authorize(http.MethodGet, params))
	})
}

// REQ-CORE-16, REQ-CORE-28: a decision is not left to answer a later
// request when the request it was made for fails. The code for a request
// with prompt=consent cannot be stored, so it gets server_error; the same
// request sent again shows the consent page.
//
// The failure is made by renaming the table of authorization codes, the
// one way to fail that request alone through a real database.
func TestConsentDecisionAfterFailure(t *testing.T) {
	t.Parallel()

	pool := postgrestest.Open(t, postgrestest.NewDatabase(t))
	b := &browser{t: t, handler: newFlowHandler(t, pool)}
	wantCode(t, b.decide(b.signIn(b.authorize(http.MethodGet, authorizationParams())), "allow"), "first request")

	params := requestWith(url.Values{"prompt": {"consent"}})
	page := parseConsentPage(t, b.authorize(http.MethodGet, params))
	next := location(t, b.submitConsent(page, url.Values{"decision": {"allow"}}, nil))
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Exec(t.Context(), sql); err != nil {
			t.Fatalf("Exec(%q) error = %v", sql, err)
		}
	}
	exec("ALTER TABLE authorization_codes RENAME TO authorization_codes_away")
	want := url.Values{"error": {"server_error"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}}
	if diff := cmp.Diff(want, errorResponse(t, b.send(http.MethodGet, next.RequestURI(), nil))); diff != "" {
		t.Errorf("request whose code cannot be stored: error response mismatch (-want +got):\n%s", diff)
	}
	exec("ALTER TABLE authorization_codes_away RENAME TO authorization_codes")

	parseConsentPage(t, b.authorize(http.MethodGet, params))
}

// REQ-CORE-28: the consent page describes every scope the discovery
// document says pulsar supports.
func TestConsentPageDescribesEveryScope(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	b := &browser{t: t, handler: handler}
	var discovery struct {
		ScopesSupported []string `json:"scopes_supported"`
	}
	resp := b.send(http.MethodGet, "/tenant/.well-known/openid-configuration", nil)
	if err := json.Unmarshal([]byte(resp.body), &discovery); err != nil {
		t.Fatalf("discovery document %q is not JSON: %v", resp.body, err)
	}
	resp = b.signIn(b.authorize(http.MethodGet, withScope(strings.Join(discovery.ScopesSupported, " "))))
	described := map[string]string{}
	for _, m := range consentScopeDescription.FindAllStringSubmatch(resp.body, -1) {
		described[html.UnescapeString(m[1])] = html.UnescapeString(m[2])
	}
	for _, s := range discovery.ScopesSupported {
		if described[s] == "" {
			t.Errorf("consent page for scopes %q describes %q as %q, want a description", discovery.ScopesSupported, s, described[s])
		}
	}
}

// submitConsent submits the consent form of page, as a browser does, with
// the page's hidden fields and form as its body, and with header, which
// may be nil, and returns the response.
func (b *browser) submitConsent(page consentPage, form url.Values, header http.Header) response {
	b.t.Helper()
	body := maps.Clone(page.hidden)
	maps.Copy(body, form)
	req := httptest.NewRequestWithContext(b.t.Context(), http.MethodPost, "https://op.example"+page.action.RequestURI(), strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	maps.Copy(req.Header, header)
	return b.do(req)
}

// wantCode fails the test unless resp redirects to rp with a code.
func wantCode(t *testing.T, resp response, what string) {
	t.Helper()
	if resp.status != http.StatusSeeOther {
		t.Fatalf("%s status = %d, want %d and a code; body %q", what, resp.status, http.StatusSeeOther, resp.body)
	}
	callback := location(t, resp)
	if got := withoutQuery(callback); got != rpRedirectURI || callback.Query().Get("code") == "" {
		t.Fatalf("%s redirected to %q, want a code at %q", what, callback, rpRedirectURI)
	}
}

// requestWith returns authorizationParams with each parameter of set set
// to its values in set.
func requestWith(set url.Values) url.Values {
	params := authorizationParams()
	maps.Copy(params, set)
	return params
}

// withScope returns authorizationParams with scope.
func withScope(scope string) url.Values {
	return requestWith(url.Values{"scope": {scope}})
}

// REQ-CORE-16, REQ-CORE-28: a Consent is remembered per End-User and
// Client. A request for scopes already allowed skips the consent page; one
// for a scope not yet allowed shows it again, and allowing it widens the
// Consent; prompt=consent shows the page even when the Consent covers the
// request, and allowing it there issues a code, not the page again.
func TestConsentRemembered(t *testing.T) {
	t.Parallel()

	b := &browser{t: t, handler: newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))}
	wantCode(t, b.decide(b.signIn(b.authorize(http.MethodGet, withScope("openid profile"))), "allow"), "first request, allowed")

	wantCode(t, b.authorize(http.MethodGet, withScope("openid profile")), "request for the scopes allowed")
	wantCode(t, b.authorize(http.MethodGet, withScope("profile openid")), "request for the scopes allowed, in another order")

	resp := b.authorize(http.MethodGet, withScope("openid email"))
	if diff := cmp.Diff([]string{"openid", "email"}, parseConsentPage(t, resp).scopes); diff != "" {
		t.Errorf("request for a scope not yet allowed: consent page scopes mismatch (-want +got):\n%s", diff)
	}
	wantCode(t, b.decide(resp, "allow"), "request for a scope not yet allowed, allowed")
	wantCode(t, b.authorize(http.MethodGet, withScope("openid profile email")), "request for the scopes allowed in two Consents")

	resp = b.authorize(http.MethodGet, requestWith(url.Values{"scope": {"openid profile"}, "prompt": {"consent"}}))
	parseConsentPage(t, resp)
	wantCode(t, b.decide(resp, "allow"), "prompt=consent, allowed")
}

// REQ-OAUTH-23, REQ-CORE-27: the consent page cannot be skipped except by
// the End-User's own submission of its form, in their browser, for the
// request it was shown for. Parameters added to the authorization request,
// a decision for another request or in another browser, a cross-origin
// submission, or a scope added to the form's body do not count.
func TestConsentCannotBeForged(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// forge acts on b, signed in as alice without a Consent, and
		// returns the request that must still show the consent page.
		forge func(b *browser) url.Values
	}{
		{
			name: "decision in the authorization request",
			forge: func(*browser) url.Values {
				return requestWith(url.Values{"scope": {"openid profile"}, "decision": {"allow"}, "allowed": {"allow"}, "consent": {"allow"}})
			},
		},
		{
			name: "decision for another request",
			forge: func(b *browser) url.Values {
				t := b.t
				page := parseConsentPage(t, b.authorize(http.MethodGet, withScope("openid")))
				b.submitConsent(page, url.Values{"decision": {"allow"}}, nil)
				return withScope("openid profile")
			},
		},
		{
			name: "decision in another browser",
			forge: func(b *browser) url.Values {
				t := b.t
				other := &browser{t: t, handler: b.handler}
				page := parseConsentPage(t, other.signIn(other.authorize(http.MethodGet, withScope("openid profile"))))
				other.submitConsent(page, url.Values{"decision": {"allow"}}, nil)
				return withScope("openid profile")
			},
		},
		{
			name: "cross-origin submission",
			forge: func(b *browser) url.Values {
				t := b.t
				params := withScope("openid profile")
				page := parseConsentPage(t, b.authorize(http.MethodGet, params))
				resp := b.submitConsent(page, url.Values{"decision": {"allow"}}, http.Header{"Sec-Fetch-Site": {"cross-site"}})
				if resp.status != http.StatusForbidden {
					t.Errorf("cross-origin POST %s status = %d, want %d", consentPath, resp.status, http.StatusForbidden)
				}
				return params
			},
		},
		{
			name: "scope added to the form",
			forge: func(b *browser) url.Values {
				t := b.t
				page := parseConsentPage(t, b.authorize(http.MethodGet, withScope("openid")))
				resp := b.submitConsent(page, url.Values{"decision": {"allow"}, "scope": {"openid profile"}}, nil)
				wantCode(t, b.send(http.MethodGet, location(t, resp).RequestURI(), nil), "allowed with a scope added to the form")
				return withScope("openid profile")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := &browser{t: t, handler: newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))}
			b.signIn(b.authorize(http.MethodGet, withScope("openid email")))
			params := tt.forge(b)
			parseConsentPage(t, b.authorize(http.MethodGet, params))
		})
	}
}
