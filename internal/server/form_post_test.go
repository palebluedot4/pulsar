package server

import (
	"crypto/sha256"
	"encoding/base64"
	"html"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/palebluedot4/pulsar/internal/config"
	"github.com/palebluedot4/pulsar/internal/guessing"
	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
	"github.com/palebluedot4/pulsar/internal/registry"
	"github.com/palebluedot4/pulsar/internal/signing"
)

// What the form-post page holds, as its template writes it.
var (
	formPostForm   = regexp.MustCompile(`(?s)<form method="post" action="([^"]*)">(.*?)</form>`)
	formPostHidden = regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)">`)
	formPostButton = regexp.MustCompile(`<button type="submit">[^<]+</button>`)
	formPostScript = regexp.MustCompile(`(?s)<script>(.*?)</script>`)
)

// formPost is a form-post page: the URL its form posts to, and the
// parameters it posts.
type formPost struct {
	action string
	params url.Values
}

// parseFormPost returns the form-post page that resp shows, failing the
// test unless it is one: a 200 page, with the headers of pulsar's pages,
// whose one form, which a visible button submits, is also submitted by
// its one script, which the Content-Security-Policy allows by its hash
// and no other way.
func parseFormPost(t *testing.T, resp response) formPost {
	t.Helper()
	if resp.status != http.StatusOK {
		t.Fatalf("status = %d, want %d and the form-post page; Location %q, body %q", resp.status, http.StatusOK, resp.header.Get("Location"), resp.body)
	}
	forms := formPostForm.FindAllStringSubmatch(resp.body, -1)
	if len(forms) != 1 {
		t.Fatalf("body = %q, want one form with method post", resp.body)
	}
	if !formPostButton.MatchString(forms[0][2]) {
		t.Errorf("form = %q, want a submit button for a browser without script", forms[0][2])
	}
	params := url.Values{}
	for _, m := range formPostHidden.FindAllStringSubmatch(forms[0][2], -1) {
		params.Add(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
	}

	scripts := formPostScript.FindAllStringSubmatch(resp.body, -1)
	if len(scripts) != 1 || !strings.Contains(scripts[0][1], "submit()") {
		t.Fatalf("body = %q, want one script that submits the form", resp.body)
	}
	// A hash-source (CSP Level 3 §2.3.1): the script's text, hashed with
	// SHA-256 and base64-encoded.
	sum := sha256.Sum256([]byte(scripts[0][1]))
	wantHeader := map[string]string{
		"Content-Type":            "text/html; charset=utf-8",
		"Cache-Control":           "no-store",
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "default-src 'none'; script-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'; frame-ancestors 'none'",
		"Location":                "",
	}
	if diff := cmp.Diff(wantHeader, headers(resp.header, wantHeader)); diff != "" {
		t.Errorf("form-post page headers mismatch (-want +got):\n%s", diff)
	}
	return formPost{action: html.UnescapeString(forms[0][1]), params: params}
}

// withFormPost returns the parameters of requestWith(set), with
// response_mode=form_post.
func withFormPost(set url.Values) url.Values {
	params := requestWith(set)
	params.Set("response_mode", "form_post")
	return params
}

// REQ-FORMPOST-1, REQ-FORMPOST-2, REQ-FORMPOST-3, REQ-FORMPOST-4,
// REQ-CORE-66, REQ-ISS-2, REQ-BCP-2: with response_mode=form_post, the
// authorization response is a page whose form posts the code, state and
// iss to the redirect URI. The page submits itself with the one script
// its Content-Security-Policy allows, has a button for a browser without
// script, may not be framed or cached, and the code redeems as one sent
// in the query does.
func TestFormPostFlow(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	b := &browser{t: t, handler: handler}
	page := parseFormPost(t, b.decide(b.signIn(b.authorize(http.MethodGet, withFormPost(nil))), "allow"))
	if page.action != rpRedirectURI {
		t.Errorf("form action = %q, want %q", page.action, rpRedirectURI)
	}
	code := page.params.Get("code")
	want := url.Values{"code": {code}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}}
	if diff := cmp.Diff(want, page.params); diff != "" {
		t.Errorf("form-post parameters mismatch (-want +got):\n%s", diff)
	}
	wantAtLeast160Bits(t, "form-post code", code)
	verify(t, handler, redeem(t, handler, code))
}

// REQ-FORMPOST-1, REQ-FORMPOST-2, REQ-CORE-67, REQ-CORE-29, REQ-OAUTH-5,
// REQ-OAUTH-22, REQ-ISS-2: with response_mode=form_post, every error the
// authorization endpoint sends the Client comes by form_post too, with
// state and iss: one found in any parameter, a missing response_type
// among them, login_required for prompt=none, and access_denied from the
// consent page. The form posts to the redirect URI as registered, with
// its query.
func TestFormPostErrors(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	tests := []struct {
		name       string
		set        url.Values
		del        string                            // a parameter to remove
		respond    func(*browser, response) response // what the End-User does first; nil for nothing
		wantAction string                            // default rpRedirectURI
		want       url.Values
	}{
		{
			name: "no response_type",
			del:  "response_type",
			want: url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}},
		},
		{
			name: "response_type token",
			set:  url.Values{"response_type": {"token"}},
			want: url.Values{"error": {"unsupported_response_type"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}},
		},
		{
			name: "repeated scope",
			set:  url.Values{"scope": {"openid", "openid profile"}},
			want: url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}},
		},
		{
			name: "request",
			set:  url.Values{"request": {"eyJhbGciOiJub25lIn0.e30."}},
			want: url.Values{"error": {"request_not_supported"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}},
		},
		{
			name: "scope without openid",
			set:  url.Values{"scope": {"profile"}},
			want: url.Values{"error": {"invalid_scope"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}},
		},
		{
			name: "prompt=none without a Login Session",
			set:  url.Values{"prompt": {"none"}},
			want: url.Values{"error": {"login_required"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}},
		},
		{
			name:    "denied on the consent page",
			respond: func(b *browser, resp response) response { return b.decide(b.signIn(resp), "deny") },
			want:    url.Values{"error": {"access_denied"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}},
		},
		{
			name:       "redirect URI with a query",
			set:        url.Values{"redirect_uri": {rpQueryRedirectURI}},
			del:        "response_type",
			wantAction: rpQueryRedirectURI,
			want:       url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}},
		},
		{
			name: "no state",
			set:  url.Values{"response_type": {"token"}},
			del:  "state",
			want: url.Values{"error": {"unsupported_response_type"}, "iss": {loginIssuer}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			params := withFormPost(tt.set)
			params.Del(tt.del)
			b := &browser{t: t, handler: handler}
			resp := b.authorize(http.MethodGet, params)
			if tt.respond != nil {
				resp = tt.respond(b, resp)
			}
			page := parseFormPost(t, resp)
			wantAction := tt.wantAction
			if wantAction == "" {
				wantAction = rpRedirectURI
			}
			if page.action != wantAction {
				t.Errorf("form action = %q, want %q", page.action, wantAction)
			}
			if got := page.params.Get("error_description"); got == "" {
				t.Errorf("form-post error_description = %q, want a description", got)
			}
			page.params.Del("error_description")
			if diff := cmp.Diff(tt.want, page.params); diff != "" {
				t.Errorf("form-post error response mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// REQ-FORMPOST-1: a state that holds markup is posted back unchanged, as
// the value of its hidden input, and adds nothing to the page: no element,
// no attribute, no script.
func TestFormPostEscapesState(t *testing.T) {
	t.Parallel()

	const state = `"><script>alert(1)</script><input name='x' value="&amp;`
	b := &browser{t: t, handler: newFlowHandlerWithoutDatabase(t)}
	params := withFormPost(url.Values{"state": {state}})
	params.Del("response_type")
	resp := b.authorize(http.MethodGet, params)
	page := parseFormPost(t, resp)
	if diff := cmp.Diff([]string{state}, page.params["state"]); diff != "" {
		t.Errorf("form-post state mismatch (-want +got):\n%s", diff)
	}
	for _, markup := range []string{"<script>alert", "<input name='x'", `value="&amp;`} {
		if strings.Contains(resp.body, markup) {
			t.Errorf("form-post page holds %q unescaped; body %q", markup, resp.body)
		}
	}
}

// REQ-CORE-67, REQ-OAUTH-5: a response_mode pulsar does not
// support, or one repeated, is refused with invalid_request, by query, the
// default Response Mode of the response type code.
func TestUnsupportedResponseMode(t *testing.T) {
	t.Parallel()

	handler := newFlowHandlerWithoutDatabase(t)
	tests := []struct {
		name string
		mode []string
	}{
		{name: "fragment", mode: []string{"fragment"}},
		{name: "jwt", mode: []string{"jwt"}},
		{name: "form_post in another case", mode: []string{"FORM_POST"}},
		{name: "form_post repeated", mode: []string{"form_post", "form_post"}},
		{name: "form_post and query", mode: []string{"form_post", "query"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			params := authorizationParams()
			params["response_mode"] = tt.mode
			b := &browser{t: t, handler: handler}
			want := url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}}
			if diff := cmp.Diff(want, errorResponse(t, b.authorize(http.MethodGet, params))); diff != "" {
				t.Errorf("response_mode %q error response mismatch (-want +got):\n%s", tt.mode, diff)
			}
		})
	}
}

// nativeRedirectURI is the redirect URI of a native app, by a private-use
// URI scheme (RFC 8252 §7.1).
const nativeRedirectURI = "com.example.app:/callback"

// REQ-FORMPOST-1, REQ-CORE-67: a browser cannot POST to a redirect URI
// whose scheme is neither http nor https, so form_post asked for one is
// refused with invalid_request, by query, as is every other error of that
// request.
func TestFormPostRequiresWebRedirectURI(t *testing.T) {
	t.Parallel()

	reg, err := registry.Parse([]byte(`{"clients": [
		{"client_id": "native", "token_endpoint_auth_method": "none", "redirect_uris": ["` + nativeRedirectURI + `"]}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	pool := postgrestest.Open(t, postgrestest.UnreachableURL(t))
	handler := New(slog.New(slog.DiscardHandler), mustParse(t, loginIssuer), pool, signing.New(pool, config.Secret{}), reg, guessing.New(pool, nil), ready())

	tests := []struct {
		name string
		del  string // a parameter to remove
	}{
		{name: "valid otherwise"},
		{name: "no response_type", del: "response_type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			params := withFormPost(url.Values{"client_id": {"native"}, "redirect_uri": {nativeRedirectURI}})
			withPKCE(params)
			params.Del(tt.del)
			b := &browser{t: t, handler: handler}
			callback := location(t, b.authorize(http.MethodGet, params))
			if got := withoutQuery(callback); got != nativeRedirectURI {
				t.Fatalf("GET %s redirected to %q, want %q", authorizationPath, got, nativeRedirectURI)
			}
			got := callback.Query()
			if desc := got.Get("error_description"); desc == "" {
				t.Errorf("error_description = %q, want a description", desc)
			}
			got.Del("error_description")
			want := url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("error response mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
