package server

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"

	"github.com/palebluedot4/pulsar/internal/oidc"
	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
	"github.com/palebluedot4/pulsar/internal/registry"
)

// The secrets of the machine Clients of machineRegistry that have one.
const (
	batchSecret     = "batch secret"
	batchPostSecret = "batch post secret" //nolint:gosec // G101: a test value, guarding nothing.
)

// machineRegistry returns flowRegistry with three machine Clients, each
// registered for client_credentials alone: batch, which authenticates with
// client_secret_basic and may request ordersServer and billingServer, for
// orders:read, orders:write and billing:read; batch-post, with
// client_secret_post, and batch-jwt, with private_key_jwt by the keys of
// jwtKeys, each for orders:read at ordersServer.
func machineRegistry(t *testing.T) *registry.Registry {
	t.Helper()
	var jwks any
	if err := json.Unmarshal([]byte(jwtJWKS(t)), &jwks); err != nil {
		t.Fatal(err)
	}
	machine := func(id string, members map[string]any) map[string]any {
		c := map[string]any{
			"client_id":        id,
			"grant_types":      []string{"client_credentials"},
			"resource_servers": []string{ordersServer},
			"scope":            "orders:read",
		}
		maps.Copy(c, members)
		return c
	}
	return editedRegistry(t, func(file map[string]any) {
		file["clients"] = append(file["clients"].([]any),
			machine("batch", map[string]any{
				"token_endpoint_auth_method": "client_secret_basic", "client_secret_hash": hashPassword(t, batchSecret),
				"resource_servers": []string{ordersServer, billingServer}, "scope": "orders:read orders:write billing:read",
			}),
			machine("batch-post", map[string]any{
				"token_endpoint_auth_method": "client_secret_post", "client_secret_hash": hashPassword(t, batchPostSecret),
			}),
			machine("batch-jwt", map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks": jwks}), //nolint:gosec // G101: a method's name and public keys, not a credential.
		)
	})
}

// clientCredentialsForm returns the form of a token request for the
// client_credentials grant, for resource and scope.
func clientCredentialsForm(resource, scope string) url.Values {
	return url.Values{"grant_type": {"client_credentials"}, "resource": {resource}, "scope": {scope}}
}

// batchJWTAssertion returns a valid client assertion from batch-jwt, signed
// by its ES256 key.
func batchJWTAssertion(t *testing.T) string {
	t.Helper()
	claims := assertionClaims()
	claims["iss"], claims["sub"] = "batch-jwt", "batch-jwt"
	k := jwtKey(jose.ES256)
	return signAssertion(t, k.alg, k.key, k.kid, claims)
}

// REQ-OAUTH-48, REQ-OAUTH-49, REQ-AT-1, REQ-AT-2, REQ-AT-3, REQ-AT-4,
// REQ-AT-12, REQ-AT-15, REQ-BCP-14, REQ-BCP-15, REQ-BCP-16, REQ-BCP-17,
// REQ-RESOURCE-3, REQ-RESOURCE-8, REQ-OAUTH-13: a machine Client
// authenticates by the method it registered, client_secret_basic,
// client_secret_post or private_key_jwt, and gets, for one Resource Server
// and scopes of it, an access token signed and typed as every pulsar
// access token is, whose aud is that Resource Server's identifier, whose
// sub and client_id are its client_id, whose scope holds the scopes asked
// for, each once, and which lives ten minutes. The response holds that
// access token, its type, lifetime and scope, and no refresh token or ID
// token, and no cache may keep it.
func TestClientCredentials(t *testing.T) {
	t.Parallel()

	handler := newFlowHandlerFor(t, postgrestest.Open(t, postgrestest.NewDatabase(t)), machineRegistry(t))
	tests := []struct {
		name      string
		clientID  string
		basic     credentials // of HTTP Basic authentication, if any
		body      func(t *testing.T) url.Values
		scope     string
		wantScope string
	}{
		{
			name: "client_secret_basic", clientID: "batch", basic: credentials{"batch", batchSecret},
			scope: "orders:read", wantScope: "orders:read",
		},
		{
			name: "client_secret_basic, several scopes, one twice", clientID: "batch", basic: credentials{"batch", batchSecret},
			scope: "orders:write orders:read orders:write", wantScope: "orders:write orders:read",
		},
		{
			name: "client_secret_post", clientID: "batch-post",
			body: func(*testing.T) url.Values {
				return url.Values{"client_id": {"batch-post"}, "client_secret": {batchPostSecret}}
			},
			scope: "orders:read", wantScope: "orders:read",
		},
		{
			name: "private_key_jwt", clientID: "batch-jwt",
			body: func(t *testing.T) url.Values {
				t.Helper()
				return url.Values{"client_assertion_type": {jwtBearer}, "client_assertion": {batchJWTAssertion(t)}}
			},
			scope: "orders:read", wantScope: "orders:read",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			form := clientCredentialsForm(ordersServer, tt.scope)
			if tt.body != nil {
				maps.Copy(form, tt.body(t))
			}
			resp := tokenRequest(t, handler, tt.basic.id, tt.basic.secret, form)
			if resp.status != http.StatusOK {
				t.Fatalf("POST %s status = %d, want %d; body %q", tokenPath, resp.status, http.StatusOK, resp.body)
			}
			wantHeader := map[string]string{"Content-Type": "application/json", "Cache-Control": "no-store", "Pragma": "no-cache"}
			if diff := cmp.Diff(wantHeader, headers(resp.header, wantHeader)); diff != "" {
				t.Errorf("POST %s headers mismatch (-want +got):\n%s", tokenPath, diff)
			}
			var body map[string]any
			if err := json.Unmarshal([]byte(resp.body), &body); err != nil {
				t.Fatalf("POST %s body %q is not JSON: %v", tokenPath, resp.body, err)
			}
			accessToken, _ := body["access_token"].(string)
			wantBody := map[string]any{
				"access_token": accessToken, "token_type": "Bearer",
				"expires_in": float64(oidc.TokenLifetime.Seconds()), "scope": tt.wantScope,
			}
			if diff := cmp.Diff(wantBody, body); diff != "" {
				t.Errorf("POST %s body mismatch (-want +got):\n%s", tokenPath, diff)
			}

			at := verify(t, handler, accessToken)
			if at.alg != "RS256" || at.typ != "at+jwt" {
				t.Errorf("access token alg, typ = %q, %q, want %q, %q", at.alg, at.typ, "RS256", "at+jwt")
			}
			wantClaims := map[string]any{
				"iss": loginIssuer, "aud": ordersServer, "sub": tt.clientID, "client_id": tt.clientID,
				"scope": tt.wantScope, "iat": at.claims["iat"], "exp": at.claims["exp"], "jti": at.claims["jti"],
			}
			if diff := cmp.Diff(wantClaims, at.claims); diff != "" {
				t.Errorf("access token claims mismatch (-want +got):\n%s", diff)
			}
			iat, _ := at.claims["iat"].(float64)
			exp, _ := at.claims["exp"].(float64)
			if got, want := exp-iat, oidc.TokenLifetime.Seconds(); got != want {
				t.Errorf("access token exp - iat = %v, want %v", got, want)
			}
			if jti, _ := at.claims["jti"].(string); jti == "" {
				t.Error("access token jti is empty, want one")
			}
		})
	}
}

// REQ-AT-8, REQ-REVOKE-7, REQ-REVOKE-10: a machine Client's access token
// names no End-User and is for a Resource Server, so UserInfo refuses it;
// the revocation endpoint answers it with 200, as any access token for a
// Resource Server, and nothing is recorded for it to revoke, so it stays
// valid until it expires.
func TestClientCredentialsTokenElsewhere(t *testing.T) {
	t.Parallel()

	pool := postgrestest.Open(t, postgrestest.NewDatabase(t))
	handler := newFlowHandlerFor(t, pool, machineRegistry(t))
	accessToken := tokenResponseOf(t, tokenRequest(t, handler, "batch", batchSecret, clientCredentialsForm(ordersServer, "orders:read"))).AccessToken

	if got := userInfoError(t, userInfo(t, handler, getHeader, accessToken), http.StatusUnauthorized); got != "invalid_token" {
		t.Errorf("UserInfo with a machine Client's access token error = %q, want %q", got, "invalid_token")
	}
	b := &browser{t: t, handler: handler}
	wantRevocationOK(t, b.do(newRevocationRequest(t, "batch", batchSecret, revocationForm(accessToken, "access_token"))))

	var recorded int
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM access_tokens").Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if recorded != 0 {
		t.Errorf("access tokens recorded after a client_credentials grant = %d, want 0", recorded)
	}
}

// REQ-OAUTH-15, REQ-OAUTH-46, REQ-OAUTH-47, REQ-OAUTH-48, REQ-OAUTH-50,
// REQ-RESOURCE-2, REQ-RESOURCE-9, REQ-RESOURCE-10, REQ-CLIENTMETA-1,
// REQ-CLIENTMETA-3: a token request for the client_credentials grant gets
// the error RFC 6749 §5.2 or RFC 8707 §2 names, in the JSON form of RFC
// 6749 §5.2: unauthorized_client for a Client not registered for the
// grant, a public Client, or one that lists no grant_types, and for a
// machine Client using another grant; invalid_target for a resource
// missing, repeated, unknown or not permitted, or a scope of another
// Resource Server; invalid_scope for a scope missing or not registered for
// the Client, openid included. The form is checked before the Client
// authenticates, and the grant type before the resource and scope.
func TestClientCredentialsErrors(t *testing.T) {
	t.Parallel()

	handler := newFlowHandlerWithoutDatabaseFor(t, machineRegistry(t))
	batch := credentials{"batch", batchSecret}
	valid := clientCredentialsForm(ordersServer, "orders:read")
	with := func(edit func(url.Values)) url.Values {
		form := maps.Clone(valid)
		edit(form)
		return form
	}
	tests := []struct {
		name       string
		basic      credentials // of HTTP Basic authentication, if any
		form       url.Values
		wantStatus int
		wantError  string
	}{
		{name: "Client that lists no grant_types", basic: credentials{"rp", rpSecret}, form: valid, wantStatus: http.StatusBadRequest, wantError: "unauthorized_client"},
		{
			name: "Client not registered for the grant, unknown resource", basic: credentials{"rp", rpSecret},
			form:       with(func(v url.Values) { v.Set("resource", "https://api.example/unknown") }),
			wantStatus: http.StatusBadRequest, wantError: "unauthorized_client",
		},
		{
			name:       "public Client",
			form:       with(func(v url.Values) { v.Set("client_id", "public") }),
			wantStatus: http.StatusBadRequest, wantError: "unauthorized_client",
		},
		{
			name: "machine Client, authorization_code", basic: batch,
			form:       url.Values{"grant_type": {"authorization_code"}, "code": {"x"}, "redirect_uri": {rpRedirectURI}},
			wantStatus: http.StatusBadRequest, wantError: "unauthorized_client",
		},
		{
			name: "machine Client, refresh_token", basic: batch,
			form:       url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}},
			wantStatus: http.StatusBadRequest, wantError: "unauthorized_client",
		},
		{name: "wrong secret", basic: credentials{"batch", "wrong"}, form: valid, wantStatus: http.StatusUnauthorized, wantError: "invalid_client"},
		{name: "no authentication", form: valid, wantStatus: http.StatusUnauthorized, wantError: "invalid_client"},
		{name: "no resource", basic: batch, form: with(func(v url.Values) { v.Del("resource") }), wantStatus: http.StatusBadRequest, wantError: "invalid_target"},
		{name: "empty resource", basic: batch, form: with(func(v url.Values) { v.Set("resource", "") }), wantStatus: http.StatusBadRequest, wantError: "invalid_target"},
		{
			name: "no resource, wrong secret", basic: credentials{"batch", "wrong"},
			form:       with(func(v url.Values) { v.Del("resource") }),
			wantStatus: http.StatusBadRequest, wantError: "invalid_target",
		},
		{name: "resource twice", basic: batch, form: with(func(v url.Values) { v.Add("resource", ordersServer) }), wantStatus: http.StatusBadRequest, wantError: "invalid_target"},
		{name: "two resources", basic: batch, form: with(func(v url.Values) { v.Add("resource", billingServer) }), wantStatus: http.StatusBadRequest, wantError: "invalid_target"},
		{
			name: "unknown resource", basic: batch,
			form:       with(func(v url.Values) { v.Set("resource", "https://api.example/unknown") }),
			wantStatus: http.StatusBadRequest, wantError: "invalid_target",
		},
		{
			name: "resource not permitted", basic: batch,
			form:       with(func(v url.Values) { v.Set("resource", adminServer) }),
			wantStatus: http.StatusBadRequest, wantError: "invalid_target",
		},
		{name: "no scope", basic: batch, form: with(func(v url.Values) { v.Del("scope") }), wantStatus: http.StatusBadRequest, wantError: "invalid_scope"},
		{name: "blank scope", basic: batch, form: with(func(v url.Values) { v.Set("scope", " ") }), wantStatus: http.StatusBadRequest, wantError: "invalid_scope"},
		{
			name: "no scope, wrong secret", basic: credentials{"batch", "wrong"},
			form:       with(func(v url.Values) { v.Del("scope") }),
			wantStatus: http.StatusBadRequest, wantError: "invalid_scope",
		},
		{name: "scope repeated", basic: batch, form: with(func(v url.Values) { v.Add("scope", "orders:read") }), wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		{
			name: "scope of the Resource Server not registered for the Client",
			form: with(func(v url.Values) {
				v.Set("scope", "orders:write")
				v.Set("client_id", "batch-post")
				v.Set("client_secret", batchPostSecret)
			}),
			wantStatus: http.StatusBadRequest, wantError: "invalid_scope",
		},
		{name: "unknown scope", basic: batch, form: with(func(v url.Values) { v.Set("scope", "orders:read orders:delete") }), wantStatus: http.StatusBadRequest, wantError: "invalid_scope"},
		{name: "openid", basic: batch, form: with(func(v url.Values) { v.Set("scope", "openid orders:read") }), wantStatus: http.StatusBadRequest, wantError: "invalid_scope"},
		{
			name: "scope of a Resource Server the Client may not request", basic: batch,
			form:       with(func(v url.Values) { v.Set("scope", "orders:read admin") }),
			wantStatus: http.StatusBadRequest, wantError: "invalid_scope",
		},
		{
			name: "scope of another Resource Server", basic: batch,
			form:       with(func(v url.Values) { v.Set("scope", "orders:read billing:read") }),
			wantStatus: http.StatusBadRequest, wantError: "invalid_target",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tokenErrorCode(t, tokenRequest(t, handler, tt.basic.id, tt.basic.secret, tt.form), tt.wantStatus); got != tt.wantError {
				t.Errorf("POST %s error = %q, want %q", tokenPath, got, tt.wantError)
			}
		})
	}
}

// REQ-OAUTH-10, REQ-OAUTH-50: a machine Client never acts for an End-User,
// so an authorization request naming one gets the error page, which says
// so, and is never redirected, by GET or POST.
func TestClientCredentialsClientAtAuthorization(t *testing.T) {
	t.Parallel()

	handler := newFlowHandlerWithoutDatabaseFor(t, machineRegistry(t))
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			b := &browser{t: t, handler: handler}
			resp := b.authorize(method, clientParams("batch", rpRedirectURI))
			wantErrorPage(t, resp, "authorization request from a machine Client")
			if want := "not registered for the authorization code flow"; !strings.Contains(resp.body, want) {
				t.Errorf("error page body %q, want one that contains %q", resp.body, want)
			}
		})
	}
}
