package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
)

// publicRedirectURI is the redirect URI that the public Client public
// registered in flowRegistry.
const publicRedirectURI = "https://public.example/callback" //nolint:gosec // G101: a redirect URI, not a credential.

// The code_verifier and its S256 code_challenge of RFC 7636 Appendix B.
const (
	pkceVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pkceChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

// wrongVerifier is a code_verifier of the form RFC 7636 §4.1 gives, other
// than pkceVerifier.
var wrongVerifier = strings.Repeat("a", 43)

// asPublic makes params, an authorization request's, one from public.
func asPublic(params url.Values) {
	params.Set("client_id", "public")
	params.Set("redirect_uri", publicRedirectURI)
}

// withPKCE adds pkceChallenge to params, an authorization request's, by
// S256.
func withPKCE(params url.Values) {
	params.Set("code_challenge", pkceChallenge)
	params.Set("code_challenge_method", "S256")
}

// pkceClient is a Client that sends an authorization request, with or
// without PKCE, and redeems the code it gets.
type pkceClient struct {
	clientID    string
	redirectURI string
	basic       credentials // of HTTP Basic authentication, if any; a public Client sends its client_id instead
	pkce        bool        // whether the authorization request sends pkceChallenge
}

// The Clients of the tests: public with PKCE, and rp, a confidential
// Client, with and without.
var (
	publicPKCE = pkceClient{clientID: "public", redirectURI: publicRedirectURI, pkce: true}
	rpPKCE     = pkceClient{clientID: "rp", redirectURI: rpRedirectURI, basic: credentials{"rp", rpSecret}, pkce: true}
	rpNoPKCE   = pkceClient{clientID: "rp", redirectURI: rpRedirectURI, basic: credentials{"rp", rpSecret}}
)

// code returns a code issued for the Client's authorization request.
func (c pkceClient) code(t *testing.T, handler http.Handler) string {
	t.Helper()
	params := clientParams(c.clientID, c.redirectURI)
	if c.pkce {
		withPKCE(params)
	}
	return code(t, handler, params)
}

// form returns the form of a token request from the Client that redeems
// code for its redirect URI with verifier, unless it is "".
func (c pkceClient) form(code, verifier string) url.Values {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {c.redirectURI}}
	if c.basic.id == "" {
		form.Set("client_id", c.clientID)
	}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	return form
}

// redeem sends the token request with form, authenticated as the Client.
func (c pkceClient) redeem(t *testing.T, handler http.Handler, form url.Values) response {
	t.Helper()
	return tokenRequest(t, handler, c.basic.id, c.basic.secret, form)
}

// REQ-BCP-5, REQ-BCP-6, REQ-PKCE-5, REQ-OAUTH-11: a public Client redeems
// its code with its client_id and the code_verifier of the code_challenge
// it sent, by S256; a confidential Client does so with or without PKCE.
func TestPKCE(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	tests := []struct {
		name     string
		client   pkceClient
		verifier string
	}{
		{name: "public Client", client: publicPKCE, verifier: pkceVerifier},
		{name: "confidential Client with PKCE", client: rpPKCE, verifier: pkceVerifier},
		{name: "confidential Client without PKCE", client: rpNoPKCE},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			form := tt.client.form(tt.client.code(t, handler), tt.verifier)
			if got := idTokenAudience(t, handler, tt.client.redeem(t, handler, form)); got != tt.client.clientID {
				t.Errorf("POST %s ID token aud = %v, want %q", tokenPath, got, tt.client.clientID)
			}
		})
	}
}

// REQ-PKCE-4, REQ-BCP-6, REQ-BCP-7, REQ-OAUTH-11, REQ-OAUTH-26,
// REQ-OAUTH-27: a token request fails with invalid_grant when its
// code_verifier does not match the code_challenge the code was issued
// with, when it sends none for a code issued with one, or one for a code
// issued without; and with invalid_client when a Client identifies itself
// by client_id alone and is not public, when a public Client sends
// credentials, or when nothing identifies the Client.
func TestPKCETokenErrors(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	tests := []struct {
		name       string
		client     pkceClient  // the Client the code is issued to
		redeemer   *pkceClient // the Client that redeems it, if not client
		verifier   string
		edit       func(url.Values)
		wantStatus int
		wantError  string
	}{
		{name: "public Client, wrong verifier", client: publicPKCE, verifier: wrongVerifier, wantStatus: http.StatusBadRequest, wantError: "invalid_grant"},
		{name: "public Client, no verifier", client: publicPKCE, wantStatus: http.StatusBadRequest, wantError: "invalid_grant"},
		{
			name: "public Client, verifier longer than RFC 7636 allows", client: publicPKCE, verifier: strings.Repeat("a", 129),
			wantStatus: http.StatusBadRequest, wantError: "invalid_grant",
		},
		{name: "confidential Client, wrong verifier", client: rpPKCE, verifier: wrongVerifier, wantStatus: http.StatusBadRequest, wantError: "invalid_grant"},
		{name: "confidential Client, no verifier", client: rpPKCE, wantStatus: http.StatusBadRequest, wantError: "invalid_grant"},
		{
			name: "verifier for a code issued without a challenge", client: rpNoPKCE, verifier: pkceVerifier,
			wantStatus: http.StatusBadRequest, wantError: "invalid_grant",
		},
		{
			name: "repeated verifier", client: publicPKCE, verifier: pkceVerifier,
			edit:       func(v url.Values) { v.Add("code_verifier", pkceVerifier) },
			wantStatus: http.StatusBadRequest, wantError: "invalid_request",
		},
		{
			name: "public Client, no client_id", client: publicPKCE, verifier: pkceVerifier,
			edit:       func(v url.Values) { v.Del("client_id") },
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		{
			name: "public Client, unknown client_id", client: publicPKCE, verifier: pkceVerifier,
			edit:       func(v url.Values) { v.Set("client_id", "unknown") },
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		{
			name: "public Client, a client_secret", client: publicPKCE, verifier: pkceVerifier,
			edit:       func(v url.Values) { v.Set("client_secret", rpSecret) },
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		{
			name: "public Client, by Basic", client: publicPKCE, verifier: pkceVerifier,
			redeemer:   &pkceClient{clientID: "public", redirectURI: publicRedirectURI, basic: credentials{"public", ""}},
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		{
			name: "confidential Client by its client_id alone", client: rpPKCE, verifier: pkceVerifier,
			redeemer:   &pkceClient{clientID: "rp", redirectURI: rpRedirectURI},
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		{
			name: "public Client, code issued to another Client", client: rpPKCE, verifier: pkceVerifier,
			redeemer:   &pkceClient{clientID: "public", redirectURI: rpRedirectURI},
			wantStatus: http.StatusBadRequest, wantError: "invalid_grant",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			redeemer := tt.client
			if tt.redeemer != nil {
				redeemer = *tt.redeemer
			}
			form := redeemer.form(tt.client.code(t, handler), tt.verifier)
			if tt.edit != nil {
				tt.edit(form)
			}
			if got := tokenErrorCode(t, redeemer.redeem(t, handler, form), tt.wantStatus); got != tt.wantError {
				t.Errorf("POST %s error = %q, want %q", tokenPath, got, tt.wantError)
			}
		})
	}
}

// REQ-PKCE-4: a token request with a wrong code_verifier fails with
// invalid_grant. pulsar leaves the code as it was, so that the Client that
// holds the right verifier still redeems it, once.
func TestPKCEWrongVerifierKeepsCode(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	c := publicPKCE.code(t, handler)
	wrong, right := publicPKCE.form(c, wrongVerifier), publicPKCE.form(c, pkceVerifier)
	if got := tokenErrorCode(t, publicPKCE.redeem(t, handler, wrong), http.StatusBadRequest); got != "invalid_grant" {
		t.Errorf("POST %s with a wrong verifier error = %q, want %q", tokenPath, got, "invalid_grant")
	}
	if got := idTokenAudience(t, handler, publicPKCE.redeem(t, handler, right)); got != "public" {
		t.Errorf("POST %s with the right verifier ID token aud = %v, want %q", tokenPath, got, "public")
	}
	if got := tokenErrorCode(t, publicPKCE.redeem(t, handler, right), http.StatusBadRequest); got != "invalid_grant" {
		t.Errorf("POST %s with the right verifier again error = %q, want %q", tokenPath, got, "invalid_grant")
	}
}
