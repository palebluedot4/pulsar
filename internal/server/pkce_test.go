package server

import (
	"crypto/sha256"
	"encoding/base64"
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

// challengeOf returns the S256 code_challenge of verifier (RFC 7636 §4.2).
func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// pkceRequest is an authorization request from a Client, which then
// redeems the code it gets with a token request.
type pkceRequest struct {
	clientID    string
	redirectURI string
	basic       credentials // of HTTP Basic authentication, if any
	challenge   string      // the S256 code_challenge sent, if any
}

// The authorization requests of the tests: from public with PKCE, and from
// rp, a confidential Client, with and without.
var (
	publicPKCE = pkceRequest{clientID: "public", redirectURI: publicRedirectURI, challenge: pkceChallenge}
	rpPKCE     = pkceRequest{clientID: "rp", redirectURI: rpRedirectURI, basic: credentials{"rp", rpSecret}, challenge: pkceChallenge}
	rpNoPKCE   = pkceRequest{clientID: "rp", redirectURI: rpRedirectURI, basic: credentials{"rp", rpSecret}}
)

// code returns a code issued for the request.
func (r pkceRequest) code(t *testing.T, handler http.Handler) string {
	t.Helper()
	params := clientParams(r.clientID, r.redirectURI)
	if r.challenge != "" {
		params.Set("code_challenge", r.challenge)
		params.Set("code_challenge_method", "S256")
	}
	return code(t, handler, params)
}

// form returns the form of a token request that redeems code for the
// request's redirect URI with verifier, unless it is "", and that
// identifies a public Client by its client_id.
func (r pkceRequest) form(code, verifier string) url.Values {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {r.redirectURI}}
	if r.basic.id == "" {
		form.Set("client_id", r.clientID)
	}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	return form
}

// redeem sends the token request with form, authenticated as the request's
// Client.
func (r pkceRequest) redeem(t *testing.T, handler http.Handler, form url.Values) response {
	t.Helper()
	return tokenRequest(t, handler, r.basic.id, r.basic.secret, form)
}

// REQ-BCP-5, REQ-BCP-6, REQ-PKCE-5, REQ-PKCE-6, REQ-OAUTH-11,
// REQ-OAUTH-28: a public Client redeems its code with its client_id and
// the code_verifier of the code_challenge it sent, by S256; a confidential
// Client does so with or without PKCE.
func TestPKCE(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	longest := strings.Repeat("~", 128) // the longest code_verifier RFC 7636 §4.1 allows
	tests := []struct {
		name     string
		req      pkceRequest
		verifier string
	}{
		{name: "public Client", req: publicPKCE, verifier: pkceVerifier},
		{
			name:     "public Client, verifier of 128 characters",
			req:      pkceRequest{clientID: "public", redirectURI: publicRedirectURI, challenge: challengeOf(longest)},
			verifier: longest,
		},
		{name: "confidential Client with PKCE", req: rpPKCE, verifier: pkceVerifier},
		{name: "confidential Client without PKCE", req: rpNoPKCE},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			form := tt.req.form(tt.req.code(t, handler), tt.verifier)
			if got := idTokenAudience(t, handler, tt.req.redeem(t, handler, form)); got != tt.req.clientID {
				t.Errorf("POST %s ID token aud = %v, want %q", tokenPath, got, tt.req.clientID)
			}
		})
	}
}

// REQ-PKCE-4, REQ-PKCE-6, REQ-BCP-6, REQ-BCP-7, REQ-OAUTH-11,
// REQ-OAUTH-26, REQ-OAUTH-27, REQ-OAUTH-28: a token request fails with
// invalid_grant when its code_verifier does not match the code_challenge
// the code was issued with, when it sends none for a code issued with
// one, or one for a code issued without; with invalid_request when the
// code_verifier is malformed; and with invalid_client when a Client
// identifies itself by client_id alone and is not public, or when a
// public Client sends credentials, or nothing identifies the Client.
func TestPKCETokenErrors(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	// A well-formed verifier other than pkceVerifier.
	wrong := strings.Repeat("a", 43)
	// A verifier one character too short.
	short := pkceVerifier[1:]
	tests := []struct {
		name       string
		req        pkceRequest // the request the code is issued for, and how it is redeemed
		verifier   string
		edit       func(url.Values)
		basic      *credentials // overrides req.basic, if not nil
		wantStatus int
		wantError  string
	}{
		{name: "public Client, wrong verifier", req: publicPKCE, verifier: wrong, wantStatus: http.StatusBadRequest, wantError: "invalid_grant"},
		{name: "public Client, no verifier", req: publicPKCE, wantStatus: http.StatusBadRequest, wantError: "invalid_grant"},
		{name: "confidential Client, wrong verifier", req: rpPKCE, verifier: wrong, wantStatus: http.StatusBadRequest, wantError: "invalid_grant"},
		{name: "confidential Client, no verifier", req: rpPKCE, wantStatus: http.StatusBadRequest, wantError: "invalid_grant"},
		{
			name: "verifier for a code issued without a challenge", req: rpNoPKCE, verifier: pkceVerifier,
			wantStatus: http.StatusBadRequest, wantError: "invalid_grant",
		},
		{
			name:     "verifier one character short, matching its challenge",
			req:      pkceRequest{clientID: "public", redirectURI: publicRedirectURI, challenge: challengeOf(short)},
			verifier: short, wantStatus: http.StatusBadRequest, wantError: "invalid_request",
		},
		{
			name: "verifier one character long", req: publicPKCE, verifier: strings.Repeat("a", 129),
			wantStatus: http.StatusBadRequest, wantError: "invalid_request",
		},
		{
			name: "verifier with a character that is not unreserved", req: publicPKCE, verifier: strings.Repeat("a", 42) + "+",
			wantStatus: http.StatusBadRequest, wantError: "invalid_request",
		},
		{
			name: "repeated verifier", req: publicPKCE, verifier: pkceVerifier,
			edit:       func(v url.Values) { v.Add("code_verifier", pkceVerifier) },
			wantStatus: http.StatusBadRequest, wantError: "invalid_request",
		},
		{
			name: "public Client, no client_id", req: publicPKCE, verifier: pkceVerifier,
			edit:       func(v url.Values) { v.Del("client_id") },
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		{
			name: "public Client, unknown client_id", req: publicPKCE, verifier: pkceVerifier,
			edit:       func(v url.Values) { v.Set("client_id", "unknown") },
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		{
			name: "public Client, a client_secret", req: publicPKCE, verifier: pkceVerifier,
			edit:       func(v url.Values) { v.Set("client_secret", rpSecret) },
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		{
			name: "public Client, by Basic", req: publicPKCE, verifier: pkceVerifier,
			edit:       func(v url.Values) { v.Del("client_id") },
			basic:      &credentials{"public", ""},
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		{
			name: "confidential Client by its client_id alone", req: rpPKCE, verifier: pkceVerifier,
			edit:       func(v url.Values) { v.Set("client_id", "rp") },
			basic:      &credentials{},
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		{
			name: "public Client, code issued to another Client", req: rpPKCE, verifier: pkceVerifier,
			edit:       func(v url.Values) { v.Set("client_id", "public") },
			basic:      &credentials{},
			wantStatus: http.StatusBadRequest, wantError: "invalid_grant",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			form := tt.req.form(tt.req.code(t, handler), tt.verifier)
			if tt.edit != nil {
				tt.edit(form)
			}
			req := tt.req
			if tt.basic != nil {
				req.basic = *tt.basic
			}
			if got := tokenErrorCode(t, req.redeem(t, handler, form), tt.wantStatus); got != tt.wantError {
				t.Errorf("POST %s error = %q, want %q", tokenPath, got, tt.wantError)
			}
		})
	}
}

// REQ-PKCE-4: a token request with a wrong code_verifier does not use up
// the code, so the Client that holds the right one still redeems it, once.
func TestPKCEWrongVerifierKeepsCode(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	c := publicPKCE.code(t, handler)
	if got := tokenErrorCode(t, publicPKCE.redeem(t, handler, publicPKCE.form(c, strings.Repeat("a", 43))), http.StatusBadRequest); got != "invalid_grant" {
		t.Errorf("POST %s with a wrong verifier error = %q, want %q", tokenPath, got, "invalid_grant")
	}
	form := publicPKCE.form(c, pkceVerifier)
	if got := idTokenAudience(t, handler, publicPKCE.redeem(t, handler, form)); got != "public" {
		t.Errorf("POST %s with the right verifier ID token aud = %v, want %q", tokenPath, got, "public")
	}
	if got := tokenErrorCode(t, publicPKCE.redeem(t, handler, form), http.StatusBadRequest); got != "invalid_grant" {
		t.Errorf("POST %s with the right verifier again error = %q, want %q", tokenPath, got, "invalid_grant")
	}
}
