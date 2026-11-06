package server

import (
	"html"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
)

// consentPath is the path the consent form is submitted to, under
// loginIssuer.
const consentPath = "/tenant/consent"

// What the consent page shows, as its template writes it.
var (
	consentClient = regexp.MustCompile(`<strong id="client">([^<]*)</strong>`)
	consentScope  = regexp.MustCompile(`<li><code>([^<]*)</code>`)
	consentAction = regexp.MustCompile(`<form method="post" action="([^"]*)">`)
)

// consentPage is a consent page: the Client it names, the scopes it lists,
// and the URL its form is submitted to.
type consentPage struct {
	client string
	scopes []string
	action *url.URL
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
	return consentPage{client: html.UnescapeString(client[1]), scopes: scopes, action: u}
}

// decide submits the consent form of the page resp shows with decision,
// "allow" or "deny", and follows the redirect back to the authorization
// endpoint, returning its response.
func (b *browser) decide(resp response, decision string) response {
	b.t.Helper()
	page := parseConsentPage(b.t, resp)
	next := location(b.t, b.send(http.MethodPost, page.action.RequestURI(), url.Values{"decision": {decision}}))
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

// submitConsent submits the consent form of page with form as its body,
// and with header, which may be nil, and returns the response.
func (b *browser) submitConsent(page consentPage, form url.Values, header http.Header) response {
	b.t.Helper()
	req := httptest.NewRequestWithContext(b.t.Context(), http.MethodPost, "https://op.example"+page.action.RequestURI(), strings.NewReader(form.Encode()))
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

// withScope returns authorizationParams with scope, and with each pair of
// extra, a name and a value, set.
func withScope(scope string, extra ...string) url.Values {
	params := authorizationParams()
	params.Set("scope", scope)
	for i := 0; i+1 < len(extra); i += 2 {
		params.Set(extra[i], extra[i+1])
	}
	return params
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

	resp = b.authorize(http.MethodGet, withScope("openid profile", "prompt", "consent"))
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
				return withScope("openid profile", "decision", "allow", "allowed", "allow", "consent", "allow")
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
