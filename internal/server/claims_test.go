package server

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
)

// idTokenClaims are the claims every ID token holds, whatever the claims
// parameter requests.
var idTokenClaims = []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "at_hash"}

// requestedIDTokenClaims returns the claims of idToken, verified against
// the JWK Set the handler serves, other than idTokenClaims.
func requestedIDTokenClaims(t *testing.T, handler http.Handler, idToken string) map[string]any {
	t.Helper()
	claims := verify(t, handler, idToken).claims
	for _, name := range idTokenClaims {
		delete(claims, name)
	}
	return claims
}

// REQ-CORE-42, REQ-CORE-43, REQ-CORE-44, REQ-CORE-45, REQ-CORE-46,
// REQ-CORE-49: claims requested through the claims parameter are returned
// where they are asked for: in the ID token, without the scope that would
// release them to UserInfo, or from UserInfo, in addition to the claims of
// the scopes granted. A claim requested with a value or values is
// returned only if the End-User's matches one, unless a scope also
// requests it. Claims and members pulsar does not know are ignored.
func TestClaimsParameter(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	none := map[string]any{}
	tests := []struct {
		name         string
		scope        string
		claims       string
		wantIDToken  map[string]any // the claims of the ID token other than idTokenClaims
		wantUserInfo map[string]any
	}{
		{
			name: "name in the ID token", scope: "openid", claims: `{"id_token": {"name": null}}`,
			wantIDToken: map[string]any{"name": "Alice Smith"}, wantUserInfo: claimsOf(),
		},
		{
			name: "name and email from UserInfo", scope: "openid", claims: `{"userinfo": {"name": null, "email": {"essential": true}}}`,
			wantIDToken: none, wantUserInfo: claimsOf(map[string]any{"name": "Alice Smith", "email": "alice@example.com"}),
		},
		{
			name: "email in both", scope: "openid", claims: `{"id_token": {"email": null}, "userinfo": {"email": null}}`,
			wantIDToken: map[string]any{"email": "alice@example.com"}, wantUserInfo: claimsOf(map[string]any{"email": "alice@example.com"}),
		},
		{
			name: "added to the claims of the scopes", scope: "openid email", claims: `{"userinfo": {"name": null}}`,
			wantIDToken: none, wantUserInfo: claimsOf(aliceEmail, map[string]any{"name": "Alice Smith"}),
		},
		{
			name: "value that matches", scope: "openid", claims: `{"userinfo": {"email": {"value": "alice@example.com"}}}`,
			wantIDToken: none, wantUserInfo: claimsOf(map[string]any{"email": "alice@example.com"}),
		},
		{
			name: "value that does not match", scope: "openid",
			claims:      `{"userinfo": {"email": {"value": "bob@example.com"}}, "id_token": {"email_verified": {"value": false}}}`,
			wantIDToken: none, wantUserInfo: claimsOf(),
		},
		{
			name: "values, one of which matches", scope: "openid", claims: `{"id_token": {"locale": {"values": ["fr-FR", "en-US"]}}}`,
			wantIDToken: map[string]any{"locale": "en-US"}, wantUserInfo: claimsOf(),
		},
		{
			name: "values, none of which matches", scope: "openid", claims: `{"id_token": {"locale": {"values": ["fr-FR"]}}}`,
			wantIDToken: none, wantUserInfo: claimsOf(),
		},
		{
			name: "number and object values that match", scope: "openid",
			claims: `{"id_token": {"updated_at": {"value": 1700000000}, "address": {"value": {
				"formatted": "1 Main St, Springfield, 12345, US", "street_address": "1 Main St",
				"locality": "Springfield", "region": "IL", "postal_code": "12345", "country": "US"}}}}`,
			wantIDToken:  map[string]any{"updated_at": float64(1700000000), "address": aliceAddress["address"]},
			wantUserInfo: claimsOf(),
		},
		{
			name: "value that does not match a claim a scope requests", scope: "openid email",
			claims:      `{"userinfo": {"email": {"value": "bob@example.com"}}}`,
			wantIDToken: none, wantUserInfo: claimsOf(aliceEmail),
		},
		{
			name: "claims and members pulsar does not know", scope: "openid",
			claims: `{
				"userinfo": {"acr": null, "http://example.info/claims/groups": null, "family_name#ja-Kana-JP": null,
					"name": {"essential": true, "purpose": "greeting"}},
				"id_token": {"auth_time": {"essential": true}, "acr": {"values": ["urn:mace:incommon:iap:silver"]}},
				"verified_claims": {"claims": {"given_name": null}}
			}`,
			wantIDToken: none, wantUserInfo: claimsOf(map[string]any{"name": "Alice Smith"}),
		},
		{
			name: "sub from UserInfo with another value", scope: "openid", claims: `{"userinfo": {"sub": {"value": "` + bobSubject + `"}}}`,
			wantIDToken: none, wantUserInfo: claimsOf(),
		},
		{
			// The members are many, so that sub, in whichever order they
			// are read, is seldom the last.
			name: "sub with a value, and other claims", scope: "openid",
			claims: `{"id_token": {"sub": {"value": "` + aliceSubject + `"}, "name": null, "given_name": null, "family_name": null,
				"nickname": null, "website": null, "gender": null, "locale": null, "zoneinfo": null}}`,
			wantIDToken: map[string]any{
				"name": "Alice Smith", "given_name": "Alice", "family_name": "Smith", "nickname": "Ally",
				"website": "https://alice.example", "gender": "female", "locale": "en-US", "zoneinfo": "Europe/Paris",
			},
			wantUserInfo: claimsOf(),
		},
		{name: "an empty object", scope: "openid", claims: `{}`, wantIDToken: none, wantUserInfo: claimsOf()},
		{name: "null members", scope: "openid", claims: `{"userinfo": null, "id_token": null}`, wantIDToken: none, wantUserInfo: claimsOf()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			accessToken, idToken := issuedTokens(t, handler, requestWith(url.Values{"scope": {tt.scope}, "claims": {tt.claims}}))
			if diff := cmp.Diff(tt.wantIDToken, requestedIDTokenClaims(t, handler, idToken)); diff != "" {
				t.Errorf("ID token claims mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantUserInfo, userInfoClaims(t, userInfo(t, handler, getHeader, accessToken))); diff != "" {
				t.Errorf("UserInfo claims mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// REQ-CORE-42: a claims parameter that is not a JSON object of the form
// OpenID Connect Core 1.0 §5.5 gives, or that is repeated, is
// invalid_request.
func TestClaimsParameterInvalid(t *testing.T) {
	t.Parallel()

	handler := newFlowHandlerWithoutDatabase(t)
	tests := []struct {
		name   string
		claims []string
	}{
		{name: "not JSON", claims: []string{`{"userinfo":`}},
		{name: "an array", claims: []string{`[]`}},
		{name: "null", claims: []string{`null`}},
		{name: "userinfo a string", claims: []string{`{"userinfo": "name"}`}},
		{name: "id_token an array", claims: []string{`{"id_token": ["name"]}`}},
		{name: "a claim request a string", claims: []string{`{"userinfo": {"name": "yes"}}`}},
		{name: "a claim request an array", claims: []string{`{"id_token": {"name": []}}`}},
		{name: "values not an array", claims: []string{`{"userinfo": {"name": {"values": "Alice Smith"}}}`}},
		{name: "a member given twice", claims: []string{`{"userinfo": {"name": null}, "userinfo": {"email": null}}`}},
		{name: "a claim given twice", claims: []string{`{"userinfo": {"name": null, "name": {"value": "Bob"}}}`}},
		{name: "sub with a value that is not a string", claims: []string{`{"id_token": {"sub": {"value": 1}}}`}},
		{name: "sub with an empty set of values", claims: []string{`{"id_token": {"sub": {"values": []}}}`}},
		{name: "repeated", claims: []string{`{}`, `{}`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := &browser{t: t, handler: handler}
			resp := b.authorize(http.MethodGet, requestWith(url.Values{"claims": tt.claims}))
			want := url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}}
			if diff := cmp.Diff(want, errorResponse(t, resp)); diff != "" {
				t.Errorf("claims %q: error response mismatch (-want +got):\n%s", tt.claims, diff)
			}
		})
	}
}

// REQ-CORE-28, REQ-CORE-47: a claim requested through the claims
// parameter is released only with the End-User's Consent to the scope
// that requests it. The consent page asks for that scope, and allowing it
// remembers it. A claim requested with an empty set of values, which no
// value matches, asks for no scope.
func TestClaimsParameterConsent(t *testing.T) {
	t.Parallel()

	b := &browser{t: t, handler: newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))}
	resp := b.signIn(b.authorize(http.MethodGet, requestWith(url.Values{"scope": {"openid"}, "claims": {`{"id_token": {"name": null}}`}})))
	if diff := cmp.Diff([]string{"openid", "profile"}, parseConsentPage(t, resp).scopes); diff != "" {
		t.Errorf("consent page for name in the ID token scopes mismatch (-want +got):\n%s", diff)
	}
	wantCode(t, b.decide(resp, "allow"), "request for name in the ID token, allowed")

	// The Consent now covers profile, and no other scope.
	wantCode(t, b.authorize(http.MethodGet, requestWith(url.Values{"scope": {"openid profile"}, "prompt": {"none"}})), "request for profile")
	resp = b.authorize(http.MethodGet, requestWith(url.Values{"scope": {"openid"}, "claims": {`{"userinfo": {"email": null}}`}}))
	if diff := cmp.Diff([]string{"openid", "email"}, parseConsentPage(t, resp).scopes); diff != "" {
		t.Errorf("consent page for email from UserInfo scopes mismatch (-want +got):\n%s", diff)
	}
	wantCode(t, b.authorize(http.MethodGet, requestWith(url.Values{"scope": {"openid"}, "claims": {`{"id_token": {"email": {"values": []}}}`}})),
		"request for email in the ID token with an empty set of values")
}

// REQ-CORE-48: a request for the sub Claim in the ID token with a value
// gets a positive response only for the End-User that value names, as
// id_token_hint does (TestIDTokenHint): the one signed in, or one who signs
// in for the request. One for another End-User gets login_required, at
// once with prompt=none, and otherwise once the End-User who signs in is
// not the one it names. Combined with an id_token_hint that names another
// End-User, it is invalid_request. A request for the sub Claim without a
// value names no End-User.
func TestClaimsParameterSubValue(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	b := &browser{t: t, handler: handler}
	aliceIDToken := idToken(t, handler, b.decide(b.signIn(b.authorize(http.MethodGet, authorizationParams())), "allow"))
	subValue := func(sub string) string { return `{"id_token": {"sub": {"value": "` + sub + `"}}}` }
	loginRequired := url.Values{"error": {"login_required"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}}
	invalidRequest := url.Values{"error": {"invalid_request"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}}
	unchanged := func(_ *browser, resp response) response { return resp }

	tests := []struct {
		name    string
		set     url.Values
		respond func(b *browser, resp response) response
		want    url.Values // the error response; nil for a code
	}{
		{name: "alice's, prompt=none", set: url.Values{"claims": {subValue(aliceSubject)}, "prompt": {"none"}}, respond: unchanged},
		{name: "no value, prompt=none", set: url.Values{"claims": {`{"id_token": {"sub": {"essential": true}}}`}, "prompt": {"none"}}, respond: unchanged},
		{
			name: "values, alice's among them", respond: unchanged,
			set: url.Values{"claims": {`{"id_token": {"sub": {"values": ["` + bobSubject + `", "` + aliceSubject + `"]}}}`}},
		},
		{
			name: "alice's, with alice's id_token_hint", respond: unchanged,
			set: url.Values{"claims": {subValue(aliceSubject)}, "id_token_hint": {aliceIDToken}},
		},
		{name: "bob's, prompt=none", set: url.Values{"claims": {subValue(bobSubject)}, "prompt": {"none"}}, respond: unchanged, want: loginRequired},
		{name: "bob's, alice signs in again", set: url.Values{"claims": {subValue(bobSubject)}}, respond: (*browser).reauthenticate, want: loginRequired},
		{
			name: "bob's, bob signs in", set: url.Values{"claims": {subValue(bobSubject)}},
			respond: func(b *browser, resp response) response {
				resp = b.signInAs(resp, "bob", bobPassword)
				if resp.status == http.StatusOK {
					resp = b.decide(resp, "allow")
				}
				return resp
			},
		},
		{
			name: "bob's, with alice's id_token_hint", respond: unchanged,
			set:  url.Values{"claims": {subValue(bobSubject)}, "id_token_hint": {aliceIDToken}},
			want: invalidRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := &browser{t: t, handler: handler}
			wantCode(t, b.signIn(b.authorize(http.MethodGet, authorizationParams())), "alice's request")
			resp := tt.respond(b, b.authorize(http.MethodGet, requestWith(tt.set)))
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
