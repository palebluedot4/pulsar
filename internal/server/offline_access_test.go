package server

import (
	"crypto/sha256"
	"net/http"
	"net/url"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
)

// offlineAccessParams returns authorizationParams asking for offline
// access, as OpenID Connect Core 1.0 §11 has a Client ask: with
// offline_access in the scope and prompt=consent.
func offlineAccessParams() url.Values {
	return requestWith(url.Values{"scope": {"openid offline_access"}, "prompt": {"consent"}})
}

// REQ-CORE-52, REQ-CORE-53, REQ-OAUTH-30: a request with offline_access
// and prompt=consent, from a confidential or a public Client, lists
// offline access on the consent page, with what it allows; allowing it
// yields a token response with a refresh token and with offline_access in
// its scope.
func TestOfflineAccess(t *testing.T) {
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
			params := offlineAccessParams()
			params.Set("client_id", tt.client.clientID)
			params.Set("redirect_uri", tt.client.redirectURI)
			if tt.client.challenge != "" {
				withChallenge(params, tt.client.challenge)
			}
			b := &browser{t: t, handler: handler}
			resp := b.signIn(b.authorize(http.MethodGet, params))
			if diff := cmp.Diff([]string{"openid", "offline_access"}, parseConsentPage(t, resp).scopes); diff != "" {
				t.Errorf("consent page scopes mismatch (-want +got):\n%s", diff)
			}
			described := map[string]string{}
			for _, m := range consentScopeDescription.FindAllStringSubmatch(resp.body, -1) {
				described[m[1]] = m[2]
			}
			if described["offline_access"] == "" {
				t.Errorf("consent page describes offline_access as %q, want a description", described["offline_access"])
			}

			callback := location(t, b.decide(resp, "allow"))
			form := tt.client.form(callback.Query().Get("code"), tt.verifier)
			g := tokenResponseOf(t, tt.client.redeem(t, handler, form))
			if diff := cmp.Diff("openid offline_access", g.Scope); diff != "" {
				t.Errorf("POST %s scope mismatch (-want +got):\n%s", tokenPath, diff)
			}
			if g.RefreshToken == "" {
				t.Errorf("POST %s refresh_token = %q, want a refresh token", tokenPath, g.RefreshToken)
			}
		})
	}
}

// REQ-OAUTH-21, REQ-OAUTH-31, REQ-OAUTH-41: the refresh token from a code
// issued with offline access, and the one that replaces it, are each at
// least 160 bits, and are stored only as their hashes. That the access
// tokens issued from the code and from a refresh are the family's,
// TestRefreshTokenReuseRevokesFamily shows by revoking it.
func TestRefreshTokenStorage(t *testing.T) {
	t.Parallel()

	pool := postgrestest.Open(t, postgrestest.NewDatabase(t))
	handler := newFlowHandler(t, pool)
	first := rpNoPKCE.offlineTokens(t, handler, "", nil)
	refreshed := tokenResponseOf(t, rpNoPKCE.refresh(t, handler, first.RefreshToken, ""))

	for _, issued := range []tokenResponse{first, refreshed} {
		wantAtLeast160Bits(t, "refresh_token", issued.RefreshToken)
		var holding int
		err := pool.QueryRow(t.Context(), `
			SELECT (SELECT count(*) FROM refresh_tokens r WHERE strpos(r::text, $1) > 0)
				+ (SELECT count(*) FROM refresh_token_families f WHERE strpos(f::text, $1) > 0)`,
			issued.RefreshToken,
		).Scan(&holding)
		if err != nil || holding != 0 {
			t.Errorf("rows holding the refresh token itself = %d, error %v; want 0", holding, err)
		}
		tokenHash := sha256.Sum256([]byte(issued.RefreshToken))
		var recorded bool
		err = pool.QueryRow(t.Context(), "SELECT EXISTS (SELECT FROM refresh_tokens WHERE token_hash = $1)", tokenHash[:]).Scan(&recorded)
		if err != nil || !recorded {
			t.Errorf("refresh token recorded by its hash = %t, error %v; want true", recorded, err)
		}
	}
}

// REQ-CORE-53, REQ-OAUTH-22: denying a request for offline access sends
// the Client access_denied, and no code to redeem for tokens.
func TestOfflineAccessDenied(t *testing.T) {
	t.Parallel()

	b := &browser{t: t, handler: newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))}
	got := errorResponse(t, b.decide(b.signIn(b.authorize(http.MethodGet, offlineAccessParams())), "deny"))
	want := url.Values{"error": {"access_denied"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("denied request for offline access: error response mismatch (-want +got):\n%s", diff)
	}
}

// REQ-CORE-53, REQ-CORE-28: the Consent an End-User gives when allowing
// offline access covers the other scopes, never offline access. A later
// request from the same Client without offline_access is answered from
// it; a later one with it asks again, listing offline access. The page
// is shown for any request with prompt=consent, so only the Consent's
// record shows that it lacks offline_access.
func TestOfflineAccessNotRemembered(t *testing.T) {
	t.Parallel()

	pool := postgrestest.Open(t, postgrestest.NewDatabase(t))
	handler := newFlowHandler(t, pool)
	b := &browser{t: t, handler: handler}
	params := offlineAccessParams()
	params.Set("scope", "openid profile offline_access")
	wantCode(t, b.decide(b.signIn(b.authorize(http.MethodGet, params)), "allow"), "request for offline access, allowed")

	var scopes []string
	if err := pool.QueryRow(t.Context(), "SELECT scopes FROM consents WHERE subject = $1 AND client_id = 'rp'", aliceSubject).Scan(&scopes); err != nil {
		t.Fatalf("reading alice's Consent for rp: %v", err)
	}
	slices.Sort(scopes)
	if diff := cmp.Diff([]string{"openid", "profile"}, scopes); diff != "" {
		t.Errorf("Consent after allowing offline access scopes mismatch (-want +got):\n%s", diff)
	}

	wantCode(t, b.authorize(http.MethodGet, withScope("openid profile")), "later request without offline_access")
	if diff := cmp.Diff([]string{"openid", "profile", "offline_access"}, parseConsentPage(t, b.authorize(http.MethodGet, params)).scopes); diff != "" {
		t.Errorf("consent page of a later request for offline access scopes mismatch (-want +got):\n%s", diff)
	}
}

// REQ-CORE-54: offline_access without prompt=consent is ignored. The
// request signs the End-User in, the consent page does not list offline
// access, and the token response carries no refresh token and no
// offline_access in its scope; so does the next request, which the Consent
// answers without the page, and one with prompt=none, which cannot be
// combined with prompt=consent and so never grants offline access.
func TestOfflineAccessWithoutPromptConsent(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	b := &browser{t: t, handler: handler}
	params := withScope("openid offline_access")
	resp := b.signIn(b.authorize(http.MethodGet, params))
	if diff := cmp.Diff([]string{"openid"}, parseConsentPage(t, resp).scopes); diff != "" {
		t.Errorf("consent page scopes mismatch (-want +got):\n%s", diff)
	}
	// What the token response says of offline access: its scope, and no
	// refresh token.
	offlineAccess := func(r tokenResponse) tokenResponse {
		return tokenResponse{Scope: r.Scope, RefreshToken: r.RefreshToken}
	}
	want := tokenResponse{Scope: "openid"}
	c := location(t, b.decide(resp, "allow")).Query().Get("code")
	if diff := cmp.Diff(want, offlineAccess(tokenResponseOf(t, tokenRequest(t, handler, "rp", rpSecret, codeForm(c))))); diff != "" {
		t.Errorf("POST %s scope and refresh_token mismatch (-want +got):\n%s", tokenPath, diff)
	}

	resp = b.authorize(http.MethodGet, params)
	wantCode(t, resp, "request with offline_access, answered from the Consent")
	c = location(t, resp).Query().Get("code")
	if diff := cmp.Diff(want, offlineAccess(tokenResponseOf(t, tokenRequest(t, handler, "rp", rpSecret, codeForm(c))))); diff != "" {
		t.Errorf("POST %s for the request answered from the Consent: scope and refresh_token mismatch (-want +got):\n%s", tokenPath, diff)
	}

	silent := withScope("openid offline_access")
	silent.Set("prompt", "none")
	resp = b.authorize(http.MethodGet, silent)
	wantCode(t, resp, "request with offline_access and prompt=none")
	c = location(t, resp).Query().Get("code")
	if diff := cmp.Diff(want, offlineAccess(tokenResponseOf(t, tokenRequest(t, handler, "rp", rpSecret, codeForm(c))))); diff != "" {
		t.Errorf("POST %s for the request with prompt=none: scope and refresh_token mismatch (-want +got):\n%s", tokenPath, diff)
	}
}
