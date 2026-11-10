package server

import (
	"encoding/json"
	"html"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
	"github.com/palebluedot4/pulsar/internal/registry"
)

// The identifiers of the Resource Servers in flowRegistry.
const (
	ordersServer  = "https://api.example/orders"
	billingServer = "https://api.example/billing"
	adminServer   = "https://api.example/admin"
)

// resourceServersJSON is the resource_servers member of flowRegistry's
// file.
const resourceServersJSON = `[
	{"identifier": "` + ordersServer + `", "scopes": [
		{"scope": "orders:read", "description": "read your orders"},
		{"scope": "orders:write", "description": "place orders for you"}
	]},
	{"identifier": "` + billingServer + `", "scopes": [
		{"scope": "billing:read", "description": "read your invoices"}
	]},
	{"identifier": "` + adminServer + `", "scopes": [
		{"scope": "admin", "description": "manage the shop"}
	]}
]`

// What the consent page shows of a Resource Server, as its template writes
// it.
var (
	consentResourceServer = regexp.MustCompile(`<strong id="resource-server">([^<]*)</strong>`)
	consentResourceScopes = regexp.MustCompile(`(?s)<ul id="resource-server-scopes">(.*?)</ul>`)
)

// shownResourceServer is what a consent page shows of a Resource Server:
// its identifier, and each of its scopes with its description.
type shownResourceServer struct {
	Identifier string
	Scopes     map[string]string
}

// resourceServerOnPage returns what the consent page in resp shows of a
// Resource Server; its Identifier is "" if it shows none.
func resourceServerOnPage(t *testing.T, resp response) shownResourceServer {
	t.Helper()
	parseConsentPage(t, resp)
	id := consentResourceServer.FindStringSubmatch(resp.body)
	if id == nil {
		return shownResourceServer{}
	}
	shown := shownResourceServer{Identifier: html.UnescapeString(id[1])}
	if list := consentResourceScopes.FindStringSubmatch(resp.body); list != nil {
		shown.Scopes = map[string]string{}
		for _, m := range consentScopeDescription.FindAllStringSubmatch(list[1], -1) {
			shown.Scopes[html.UnescapeString(m[1])] = html.UnescapeString(m[2])
		}
	}
	return shown
}

// issuedFor is what a Resource Server reads of an access token, once it
// has verified it, and the scope the token response says it holds.
type issuedFor struct {
	Aud, Scope, ResponseScope any
}

// issuedForOf returns what the access token of tokens is issued for.
func issuedForOf(t *testing.T, handler http.Handler, tokens tokenResponse) issuedFor {
	t.Helper()
	claims := verify(t, handler, tokens.AccessToken).claims
	return issuedFor{Aud: claims["aud"], Scope: claims["scope"], ResponseScope: tokens.Scope}
}

// REQ-RESOURCE-1: no Resource Server's scope may be one the discovery
// document lists, so that each OpenID Connect scope keeps its meaning,
// however that list grows.
func TestResourceServerScopesExcludeOpenIDConnect(t *testing.T) {
	t.Parallel()

	b := &browser{t: t, handler: newFlowHandlerWithoutDatabase(t)}
	var discovery struct {
		ScopesSupported []string `json:"scopes_supported"`
	}
	resp := b.send(http.MethodGet, "/tenant/.well-known/openid-configuration", nil)
	if err := json.Unmarshal([]byte(resp.body), &discovery); err != nil {
		t.Fatalf("discovery document %q is not JSON: %v", resp.body, err)
	}
	for _, s := range discovery.ScopesSupported {
		file := `{"resource_servers": [{"identifier": "` + ordersServer + `", "scopes": [{"scope": "` + s + `", "description": "x"}]}]}`
		if _, err := registry.Parse([]byte(file)); err == nil {
			t.Errorf("registry.Parse(a Resource Server with the scope %q) error = nil, want an error", s)
		}
	}
}

// REQ-RESOURCE-3, REQ-RESOURCE-5, REQ-RESOURCE-7, REQ-RESOURCE-8,
// REQ-AT-8, REQ-AT-12, REQ-AT-13, REQ-BCP-8, REQ-BCP-14, REQ-BCP-15,
// REQ-CORE-28: a Client asks, with resource, for an access token for a
// Resource Server it may request, and for that Resource Server's scopes
// beside OpenID Connect's. The consent page lists them, with their
// descriptions, under the Resource Server's identifier. The access token
// names the Resource Server alone in aud, and holds only its scopes, as
// the token response's scope says; UserInfo refuses it, and the ID token
// is as it is without resource, with the claims the claims parameter
// requests in it. Each refresh, with the same resource or without one,
// and for the scope granted or a narrower one, issues an access token for
// the same Resource Server.
func TestResourceServerFlow(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	b := &browser{t: t, handler: handler}
	params := requestWith(url.Values{
		"resource": {ordersServer},
		"scope":    {"openid profile orders:read orders:write offline_access"},
		"prompt":   {"consent"},
		"claims":   {`{"id_token": {"name": null}}`},
	})
	resp := b.signIn(b.authorize(http.MethodGet, params))
	wantShown := shownResourceServer{
		Identifier: ordersServer,
		Scopes:     map[string]string{"orders:read": "read your orders", "orders:write": "place orders for you"},
	}
	if diff := cmp.Diff(wantShown, resourceServerOnPage(t, resp)); diff != "" {
		t.Errorf("consent page's Resource Server mismatch (-want +got):\n%s", diff)
	}
	code := location(t, b.decide(resp, "allow")).Query().Get("code")
	if code == "" {
		t.Fatal("authorization response with resource has no code")
	}

	form := codeForm(code)
	form.Set("resource", ordersServer)
	tokens := tokenResponseOf(t, tokenRequest(t, handler, "rp", rpSecret, form))
	if tokens.Scope != "orders:read orders:write" {
		t.Errorf("POST %s with resource: scope = %q, want %q", tokenPath, tokens.Scope, "orders:read orders:write")
	}
	at := verify(t, handler, tokens.AccessToken).claims
	wantAT := map[string]any{
		"iss": loginIssuer, "aud": ordersServer, "sub": aliceSubject, "client_id": "rp",
		"scope": "orders:read orders:write", "iat": at["iat"], "exp": at["exp"], "jti": at["jti"],
	}
	if diff := cmp.Diff(wantAT, at); diff != "" {
		t.Errorf("access token for %s claims mismatch (-want +got):\n%s", ordersServer, diff)
	}
	id := verify(t, handler, tokens.IDToken).claims
	wantID := map[string]any{
		"iss": loginIssuer, "sub": aliceSubject, "aud": "rp", "nonce": "n-0S6_WzA2Mj",
		"at_hash": atHash(tokens.AccessToken), "name": "Alice Smith",
		"iat": at["iat"], "exp": at["exp"], "auth_time": id["auth_time"],
	}
	if diff := cmp.Diff(wantID, id); diff != "" {
		t.Errorf("ID token claims mismatch (-want +got):\n%s", diff)
	}
	if got := userInfoError(t, userInfo(t, handler, getHeader, tokens.AccessToken), http.StatusUnauthorized); got != "invalid_token" {
		t.Errorf("UserInfo with an access token for %s error = %q, want %q", ordersServer, got, "invalid_token")
	}

	refreshToken := tokens.RefreshToken
	refreshes := []struct {
		name      string
		resource  string
		scope     string
		wantScope string
	}{
		{name: "without resource", wantScope: "orders:read orders:write"},
		{name: "with the same resource", resource: ordersServer, wantScope: "orders:read orders:write"},
		{name: "for a narrower scope", scope: "openid orders:read", wantScope: "orders:read"},
	}
	for _, r := range refreshes {
		form := refreshForm(refreshToken, r.scope)
		if r.resource != "" {
			form.Set("resource", r.resource)
		}
		got := tokenResponseOf(t, rpNoPKCE.redeem(t, handler, form))
		want := issuedFor{Aud: ordersServer, Scope: r.wantScope, ResponseScope: r.wantScope}
		if diff := cmp.Diff(want, issuedForOf(t, handler, got)); diff != "" {
			t.Errorf("refresh %s: access token mismatch (-want +got):\n%s", r.name, diff)
		}
		refreshToken = got.RefreshToken
	}
}

// REQ-RESOURCE-3, REQ-RESOURCE-7, REQ-RESOURCE-8, REQ-AT-5, REQ-AT-13,
// REQ-AT-14, REQ-BCP-14, REQ-CORE-45: the scopes a request may be granted
// are OpenID Connect's, and those of the Resource Server its resource
// names; any other is ignored, as a scope pulsar does not know is. So
// without resource, a Resource Server's scope is ignored, and the access
// token is for pulsar's UserInfo, as it is without that scope. With
// resource, another Resource Server's scope is ignored, and so are the
// claims the claims parameter requests from UserInfo, which refuses that
// access token: the End-User is not asked for scopes nothing can release.
func TestResourceScopes(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	tests := []struct {
		name       string
		resource   string
		scope      string
		claims     string              // the claims parameter, if any
		wantPage   []string            // the scopes the consent page lists
		wantServer shownResourceServer // the Resource Server the consent page shows
		want       issuedFor
	}{
		{
			name: "a Resource Server's scope without resource", scope: "openid orders:read",
			wantPage: []string{"openid"},
			want:     issuedFor{Aud: loginIssuer, Scope: "openid", ResponseScope: "openid"},
		},
		{
			name: "another Resource Server's scope", resource: ordersServer, scope: "openid orders:read billing:read",
			wantPage:   []string{"openid", "orders:read"},
			wantServer: shownResourceServer{Identifier: ordersServer, Scopes: map[string]string{"orders:read": "read your orders"}},
			want:       issuedFor{Aud: ordersServer, Scope: "orders:read", ResponseScope: "orders:read"},
		},
		{
			name: "claims requested from UserInfo", resource: ordersServer, scope: "openid orders:read",
			claims:     `{"userinfo": {"email": null}}`,
			wantPage:   []string{"openid", "orders:read"},
			wantServer: shownResourceServer{Identifier: ordersServer, Scopes: map[string]string{"orders:read": "read your orders"}},
			want:       issuedFor{Aud: ordersServer, Scope: "orders:read", ResponseScope: "orders:read"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			params := requestWith(url.Values{"scope": {tt.scope}, "prompt": {"consent"}})
			if tt.resource != "" {
				params.Set("resource", tt.resource)
			}
			if tt.claims != "" {
				params.Set("claims", tt.claims)
			}
			b := &browser{t: t, handler: handler}
			resp := b.signIn(b.authorize(http.MethodGet, params))
			if diff := cmp.Diff(tt.wantPage, parseConsentPage(t, resp).scopes); diff != "" {
				t.Errorf("consent page scopes mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantServer, resourceServerOnPage(t, resp)); diff != "" {
				t.Errorf("consent page's Resource Server mismatch (-want +got):\n%s", diff)
			}
			form := codeForm(location(t, b.decide(resp, "allow")).Query().Get("code"))
			got := issuedForOf(t, handler, tokenResponseOf(t, tokenRequest(t, handler, "rp", rpSecret, form)))
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("access token mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// editedRegistry returns flowRegistry with its file changed by edit, as a
// deployment's registry is once its file is edited.
func editedRegistry(t *testing.T, edit func(file map[string]any)) *registry.Registry {
	t.Helper()
	var file map[string]any
	if err := json.Unmarshal(flowRegistryFile(t), &file); err != nil {
		t.Fatal(err)
	}
	edit(file)
	b, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := registry.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// REQ-CORE-16, REQ-CORE-28: a Consent covers a Resource Server's scopes as
// it covers OpenID Connect's, for that Resource Server. A request for
// scopes the End-User allowed skips the consent page; one for a scope of
// the Resource Server not yet allowed shows it again, and so does one for
// the same scopes once they belong to a Resource Server of another
// identifier, which the End-User has not allowed.
func TestResourceConsentRemembered(t *testing.T) {
	t.Parallel()

	pool := postgrestest.Open(t, postgrestest.NewDatabase(t))
	b := &browser{t: t, handler: newFlowHandler(t, pool)}
	request := func(resource, scope string) url.Values {
		return requestWith(url.Values{"scope": {scope}, "resource": {resource}})
	}
	wantCode(t, b.decide(b.signIn(b.authorize(http.MethodGet, request(ordersServer, "openid orders:read"))), "allow"), "first request, allowed")
	wantCode(t, b.authorize(http.MethodGet, request(ordersServer, "openid orders:read")), "request for the scopes allowed")

	resp := b.authorize(http.MethodGet, request(ordersServer, "openid orders:read orders:write"))
	want := shownResourceServer{
		Identifier: ordersServer,
		Scopes:     map[string]string{"orders:read": "read your orders", "orders:write": "place orders for you"},
	}
	if diff := cmp.Diff(want, resourceServerOnPage(t, resp)); diff != "" {
		t.Errorf("request for a scope not yet allowed: consent page's Resource Server mismatch (-want +got):\n%s", diff)
	}

	const renamed = "https://api.example/orders/v2"
	b.handler = newFlowHandlerFor(t, pool, editedRegistry(t, func(file map[string]any) {
		file["resource_servers"].([]any)[0].(map[string]any)["identifier"] = renamed
		for _, c := range file["clients"].([]any) {
			if client := c.(map[string]any); client["client_id"] == "rp" || client["client_id"] == "public" {
				client["resource_servers"] = []string{renamed}
			}
		}
	}))
	resp = b.authorize(http.MethodGet, request(renamed, "openid orders:read"))
	want = shownResourceServer{Identifier: renamed, Scopes: map[string]string{"orders:read": "read your orders"}}
	if diff := cmp.Diff(want, resourceServerOnPage(t, resp)); diff != "" {
		t.Errorf("request for the scopes allowed, at another identifier: consent page's Resource Server mismatch (-want +got):\n%s", diff)
	}
}

// REQ-RESOURCE-2, REQ-RESOURCE-6: once the registry no longer lets a
// Client request a Resource Server, a code or refresh token issued for it
// gets invalid_target, with resource or without; the Client cannot obtain
// an access token for it any more. Restoring the registry restores them.
func TestResourceServerNoLongerPermitted(t *testing.T) {
	t.Parallel()

	pool := postgrestest.Open(t, postgrestest.NewDatabase(t))
	handler := newFlowHandler(t, pool)
	set := url.Values{"scope": {"openid orders:read offline_access"}, "resource": {ordersServer}}
	refreshToken := rpNoPKCE.offlineTokens(t, handler, "", set).RefreshToken
	code := rpNoPKCE.offlineCode(t, handler, set)

	withdrawn := newFlowHandlerFor(t, pool, editedRegistry(t, func(file map[string]any) {
		for _, c := range file["clients"].([]any) {
			if client := c.(map[string]any); client["client_id"] == "rp" {
				client["resource_servers"] = []string{billingServer}
			}
		}
	}))

	tests := []struct {
		name string
		form url.Values
	}{
		{name: "code", form: rpNoPKCE.form(code, "")},
		{name: "refresh token", form: refreshForm(refreshToken, "")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for _, resource := range []string{"", ordersServer} {
				form := maps.Clone(tt.form)
				if resource != "" {
					form.Set("resource", resource)
				}
				if got := tokenErrorCode(t, rpNoPKCE.redeem(t, withdrawn, form), http.StatusBadRequest); got != "invalid_target" {
					t.Errorf("POST %s with resource %q, once rp may not request it: error = %q, want %q", tokenPath, resource, got, "invalid_target")
				}
			}
			tokenResponseOf(t, rpNoPKCE.redeem(t, handler, tt.form))
		})
	}
}

// REQ-RESOURCE-2, REQ-RESOURCE-5, REQ-RESOURCE-6, REQ-RESOURCE-9,
// REQ-BCP-8: a token request, for a code or a refresh token, whose
// resource is not the one the code or Refresh Token Family was issued
// for, none included, or that sends more than one, gets invalid_target in
// the JSON form of RFC 6749 §5.2, as does a refresh for a scope that holds
// none of the Resource Server's scopes. The code or refresh token stays to
// be redeemed: the same request without resource or scope then issues an
// access token for the Resource Server, or for pulsar's UserInfo if there
// is none.
func TestResourceTokenErrors(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	tests := []struct {
		name     string
		granted  string   // the authorization request's resource, if any
		refresh  bool     // whether the request redeems a refresh token rather than a code
		resource []string // the token request's resource
		scope    string   // the refresh's scope, if any
		wantAud  string   // the aud of the access token the request without resource or scope gets
	}{
		{name: "refresh, none of the Resource Server's scopes", granted: ordersServer, refresh: true, scope: "openid offline_access", wantAud: ordersServer},
		{name: "code, another resource", granted: ordersServer, resource: []string{billingServer}, wantAud: ordersServer},
		{name: "code, a resource not granted", resource: []string{ordersServer}, wantAud: loginIssuer},
		{name: "code, the resource twice", granted: ordersServer, resource: []string{ordersServer, ordersServer}, wantAud: ordersServer},
		{name: "refresh, another resource", granted: ordersServer, refresh: true, resource: []string{billingServer}, wantAud: ordersServer},
		{name: "refresh, a resource not granted", refresh: true, resource: []string{ordersServer}, wantAud: loginIssuer},
		{name: "refresh, the resource twice", granted: ordersServer, refresh: true, resource: []string{ordersServer, ordersServer}, wantAud: ordersServer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			set := url.Values{"scope": {"openid orders:read offline_access"}}
			if tt.granted != "" {
				set.Set("resource", tt.granted)
			}
			var form url.Values
			if tt.refresh {
				form = refreshForm(rpNoPKCE.offlineTokens(t, handler, "", set).RefreshToken, "")
			} else {
				form = rpNoPKCE.form(rpNoPKCE.offlineCode(t, handler, set), "")
			}

			refused := maps.Clone(form)
			if tt.resource != nil {
				refused["resource"] = tt.resource
			}
			if tt.scope != "" {
				refused.Set("scope", tt.scope)
			}
			if got := tokenErrorCode(t, rpNoPKCE.redeem(t, handler, refused), http.StatusBadRequest); got != "invalid_target" {
				t.Errorf("POST %s with resource %q, scope %q: error = %q, want %q", tokenPath, tt.resource, tt.scope, got, "invalid_target")
			}
			got := tokenResponseOf(t, rpNoPKCE.redeem(t, handler, form))
			if aud := issuedForOf(t, handler, got).Aud; aud != tt.wantAud {
				t.Errorf("POST %s without resource or scope after: access token aud = %v, want %s", tokenPath, aud, tt.wantAud)
			}
		})
	}
}

// REQ-RESOURCE-1, REQ-RESOURCE-2, REQ-RESOURCE-4, REQ-RESOURCE-9,
// REQ-ISS-2: an authorization request whose resource is not one Resource
// Server the Client may request, by its identifier exactly as registered,
// gets invalid_target at the redirect URI, with state and iss, before any
// login, by the Response Mode requested: one not registered, or registered
// for another Client only; one that is not an absolute URI, or has a
// fragment; and more than one, even the same one twice. So does one that
// asks for none of its Resource Server's scopes.
func TestResourceAuthorizationErrors(t *testing.T) {
	t.Parallel()

	handler := newFlowHandlerWithoutDatabase(t)
	tests := []struct {
		name     string
		resource []string
		scope    string // default "openid orders:read"
	}{
		{name: "not registered", resource: []string{"https://api.example/unknown"}},
		{name: "registered for another Client", resource: []string{adminServer}},
		{name: "relative", resource: []string{"/orders"}},
		{name: "not a URI", resource: []string{"orders"}},
		{name: "with a fragment", resource: []string{ordersServer + "#top"}},
		{name: "with an empty fragment", resource: []string{ordersServer + "#"}},
		{name: "with a trailing slash", resource: []string{ordersServer + "/"}},
		{name: "in another case", resource: []string{"https://API.example/orders"}},
		{name: "two Resource Servers", resource: []string{ordersServer, billingServer}},
		{name: "the same Resource Server twice", resource: []string{ordersServer, ordersServer}},
		{name: "none of its scopes", resource: []string{ordersServer}, scope: "openid profile"},
		{name: "only another Resource Server's scopes", resource: []string{ordersServer}, scope: "openid billing:read"},
	}
	want := url.Values{"error": {"invalid_target"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}}
	for _, tt := range tests {
		set := url.Values{"resource": tt.resource, "scope": {"openid orders:read"}}
		if tt.scope != "" {
			set.Set("scope", tt.scope)
		}
		t.Run(tt.name+"/query", func(t *testing.T) {
			t.Parallel()
			b := &browser{t: t, handler: handler}
			resp := b.authorize(http.MethodGet, requestWith(set))
			if got := location(t, resp).Query().Get("error_description"); got == "" {
				t.Errorf("error_description = %q, want a description", got)
			}
			if diff := cmp.Diff(want, errorResponse(t, resp)); diff != "" {
				t.Errorf("resource %q: error response mismatch (-want +got):\n%s", tt.resource, diff)
			}
		})
		t.Run(tt.name+"/form_post", func(t *testing.T) {
			t.Parallel()
			b := &browser{t: t, handler: handler}
			page := parseFormPost(t, b.authorize(http.MethodGet, withFormPost(set)))
			page.params.Del("error_description")
			if page.action != rpRedirectURI {
				t.Errorf("form action = %q, want %q", page.action, rpRedirectURI)
			}
			if diff := cmp.Diff(want, page.params); diff != "" {
				t.Errorf("resource %q: form-post error response mismatch (-want +got):\n%s", tt.resource, diff)
			}
		})
	}
}

// REQ-OAUTH-15, REQ-OAUTH-20, REQ-RESOURCE-9: a token request's more basic
// faults are answered before a repeated resource: a missing or unsupported
// grant_type, or a missing code or refresh_token, gets the error it gets
// without resource.
func TestResourceTokenRequestMalformed(t *testing.T) {
	t.Parallel()

	handler := newFlowHandlerWithoutDatabase(t)
	repeated := []string{ordersServer, billingServer}
	tests := []struct {
		name string
		form url.Values
		want string
	}{
		{name: "no grant_type", form: url.Values{"resource": repeated}, want: "invalid_request"},
		{name: "grant_type client_credentials", form: url.Values{"grant_type": {"client_credentials"}, "resource": repeated}, want: "unsupported_grant_type"},
		{name: "no code", form: url.Values{"grant_type": {"authorization_code"}, "redirect_uri": {rpRedirectURI}, "resource": repeated}, want: "invalid_request"},
		{name: "no refresh_token", form: url.Values{"grant_type": {"refresh_token"}, "resource": repeated}, want: "invalid_request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tokenErrorCode(t, tokenRequest(t, handler, "rp", rpSecret, tt.form), http.StatusBadRequest); got != tt.want {
				t.Errorf("POST %s with %s and resource twice: error = %q, want %q", tokenPath, tt.name, got, tt.want)
			}
		})
	}
}

// REQ-OAUTH-19, REQ-RESOURCE-6: a code or refresh token whose End-User is
// out of the registry gets invalid_grant, whatever its resource, as a
// Client could not obtain tokens with any other.
func TestResourceTokenEndUserRemoved(t *testing.T) {
	t.Parallel()

	pool := postgrestest.Open(t, postgrestest.NewDatabase(t))
	handler := newFlowHandler(t, pool)
	set := url.Values{"scope": {"openid orders:read offline_access"}, "resource": {ordersServer}}
	refreshToken := rpNoPKCE.offlineTokens(t, handler, "", set).RefreshToken
	code := rpNoPKCE.offlineCode(t, handler, set)
	withoutAlice := newFlowHandlerFor(t, pool, flowRegistryWithout(t, aliceSubject))

	tests := []struct {
		name string
		form url.Values
	}{
		{name: "code", form: rpNoPKCE.form(code, "")},
		{name: "refresh token", form: refreshForm(refreshToken, "")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			form := maps.Clone(tt.form)
			form.Set("resource", billingServer)
			if got := tokenErrorCode(t, rpNoPKCE.redeem(t, withoutAlice, form), http.StatusBadRequest); got != "invalid_grant" {
				t.Errorf("POST %s for a %s of an End-User removed, with another resource: error = %q, want %q", tokenPath, tt.name, got, "invalid_grant")
			}
		})
	}
}
