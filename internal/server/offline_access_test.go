package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
)

// offlineAccessParams returns authorizationParams asking for offline
// access, as OpenID Connect Core 1.0 §11 has a Client ask: with
// offline_access in the scope and prompt=consent.
func offlineAccessParams() url.Values {
	return requestWith(url.Values{"scope": {"openid offline_access"}, "prompt": {"consent"}})
}

// grant is what a successful token response grants: its scope, and its
// refresh token, if any.
type grant struct {
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
}

// grantOf returns the grant of a successful token response, failing the
// test for any other.
func grantOf(t *testing.T, resp response) grant {
	t.Helper()
	if resp.status != http.StatusOK {
		t.Fatalf("POST %s status = %d, want %d; body %q", tokenPath, resp.status, http.StatusOK, resp.body)
	}
	var g grant
	if err := json.Unmarshal([]byte(resp.body), &g); err != nil {
		t.Fatalf("POST %s body %q is not a token response: %v", tokenPath, resp.body, err)
	}
	return g
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
			g := grantOf(t, tt.client.redeem(t, handler, form))
			if g.Scope != "openid offline_access" || g.RefreshToken == "" {
				t.Errorf("POST %s scope, refresh_token = %q, %q, want %q and a refresh token", tokenPath, g.Scope, g.RefreshToken, "openid offline_access")
			}
		})
	}
}

// REQ-OAUTH-21, REQ-OAUTH-31, REQ-OAUTH-32: the refresh token from a code
// issued with offline access is at least 160 bits, and is stored only as
// its hash, in the Refresh Token Family that the code's redemption starts.
// The family records the Client, the Subject, the scopes, the claims
// request and auth_time of the authorization, and the code, and ends 30
// days after the code is redeemed; the access token issued from the code
// is the family's.
//
// Until the refresh_token grant (#51) redeems it, nothing a Client can send
// shows what the family holds, so its record is read.
func TestRefreshTokenFamilyStarted(t *testing.T) {
	t.Parallel()

	databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
	synctest.Test(t, func(t *testing.T) {
		pool, err := pgxpool.New(t.Context(), databaseURL)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		handler := newFlowHandler(t, pool)
		signedIn := time.Now()
		params := offlineAccessParams()
		params.Set("scope", "openid email offline_access")
		params.Set("claims", `{"id_token": {"email": null}}`)
		c := code(t, handler, params)
		time.Sleep(30 * time.Second)
		redeemed := time.Now()
		resp := tokenRequest(t, handler, "rp", rpSecret, codeForm(c))
		accessToken, _ := tokensOf(t, resp)
		refreshToken := grantOf(t, resp).RefreshToken
		if raw, err := base64.RawURLEncoding.DecodeString(refreshToken); err != nil || len(raw) < 20 {
			t.Errorf("POST %s refresh_token = %q, want at least 160 bits in base64url", tokenPath, refreshToken)
		}

		type family struct {
			ClientID, Subject string
			Scopes            []string
			// Whether the family holds the code's claims request, which is
			// not empty, and the code's hash.
			CodeClaims, CodeHash bool
			AuthTime, Expiry     time.Time
			Revoked              bool
			// Whether the access token issued from the code is the family's.
			HasAccessToken bool
		}
		tokenHash := sha256.Sum256([]byte(refreshToken))
		codeHash := sha256.Sum256([]byte(c))
		var got family
		err = pool.QueryRow(t.Context(), `
			SELECT f.client_id, f.subject, f.scopes,
				f.claims = c.claims AND c.claims <> '{}', f.code_hash = $2,
				f.auth_time, f.expiry, f.revoked,
				EXISTS (SELECT FROM access_tokens a WHERE a.jti = $3 AND a.family_id = f.id)
			FROM refresh_tokens r
			JOIN refresh_token_families f ON f.id = r.family_id
			JOIN authorization_codes c ON c.code_hash = f.code_hash
			WHERE r.token_hash = $1`,
			tokenHash[:], codeHash[:], verify(t, handler, accessToken).claims["jti"],
		).Scan(&got.ClientID, &got.Subject, &got.Scopes, &got.CodeClaims, &got.CodeHash,
			&got.AuthTime, &got.Expiry, &got.Revoked, &got.HasAccessToken)
		if err != nil {
			t.Fatalf("reading the family of the refresh token's hash: %v", err)
		}
		want := family{
			ClientID: "rp", Subject: aliceSubject, Scopes: []string{"openid", "email", "offline_access"},
			CodeClaims: true, CodeHash: true,
			AuthTime: signedIn, Expiry: redeemed.Add(30 * 24 * time.Hour),
			HasAccessToken: true,
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("Refresh Token Family mismatch (-want +got):\n%s", diff)
		}

		var holding int
		err = pool.QueryRow(t.Context(), `
			SELECT (SELECT count(*) FROM refresh_tokens r WHERE strpos(r::text, $1) > 0)
				+ (SELECT count(*) FROM refresh_token_families f WHERE strpos(f::text, $1) > 0)`,
			refreshToken,
		).Scan(&holding)
		if err != nil || holding != 0 {
			t.Errorf("rows holding the refresh token itself = %d, error %v; want 0", holding, err)
		}
	})
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
// it; a later one with it asks again.
//
// No request can show that the Consent lacks offline_access, since every
// request that keeps offline_access asks the End-User; so the Consent's
// record is read.
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
	parseConsentPage(t, b.authorize(http.MethodGet, params))
}

// REQ-CORE-54: offline_access without prompt=consent is ignored. The
// request signs the End-User in, the consent page does not list offline
// access, and the token response carries no refresh token and no
// offline_access in its scope; so does the next request, which the Consent
// answers without the page.
func TestOfflineAccessWithoutPromptConsent(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	b := &browser{t: t, handler: handler}
	params := withScope("openid offline_access")
	resp := b.signIn(b.authorize(http.MethodGet, params))
	if diff := cmp.Diff([]string{"openid"}, parseConsentPage(t, resp).scopes); diff != "" {
		t.Errorf("consent page scopes mismatch (-want +got):\n%s", diff)
	}
	want := grant{Scope: "openid"}
	c := location(t, b.decide(resp, "allow")).Query().Get("code")
	if diff := cmp.Diff(want, grantOf(t, tokenRequest(t, handler, "rp", rpSecret, codeForm(c)))); diff != "" {
		t.Errorf("POST %s grant mismatch (-want +got):\n%s", tokenPath, diff)
	}

	resp = b.authorize(http.MethodGet, params)
	wantCode(t, resp, "request with offline_access, answered from the Consent")
	c = location(t, resp).Query().Get("code")
	if diff := cmp.Diff(want, grantOf(t, tokenRequest(t, handler, "rp", rpSecret, codeForm(c)))); diff != "" {
		t.Errorf("POST %s for the request answered from the Consent grant mismatch (-want +got):\n%s", tokenPath, diff)
	}
}
