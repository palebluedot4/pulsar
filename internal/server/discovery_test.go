package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// REQ-DISC-2, REQ-DISC-3, REQ-DISC-4, REQ-DISC-5, REQ-DISC-6, REQ-DISC-7,
// REQ-DISC-8, REQ-DISC-9, REQ-DISC-10, REQ-DISC-11, REQ-DISC-12,
// REQ-DISC-14, REQ-DISC-15, REQ-DISC-16, REQ-DISC-17,
// REQ-ISS-1, REQ-BCP-1: the discovery document, at the path derived from
// the issuer, with the metadata spec #11 lists.
func TestDiscovery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		issuer string
		path   string // where a Client fetches the document
	}{
		{name: "issuer without path", issuer: "https://op.example", path: "/.well-known/openid-configuration"},
		{name: "issuer with path", issuer: "https://op.example/tenant", path: "/tenant/.well-known/openid-configuration"},
		{name: "loopback issuer with port", issuer: "http://127.0.0.1:8080", path: "/.well-known/openid-configuration"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tt.path, http.NoBody)
			newHandlerWithoutDatabase(t, tt.issuer).ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, want %d", tt.path, rec.Code, http.StatusOK)
			}
			wantHeader := map[string]string{
				"Content-Type":                "application/json",
				"Cache-Control":               "public, max-age=3600",
				"Access-Control-Allow-Origin": "*",
			}
			gotHeader := make(map[string]string, len(wantHeader))
			for k := range wantHeader {
				gotHeader[k] = rec.Header().Get(k)
			}
			if diff := cmp.Diff(wantHeader, gotHeader); diff != "" {
				t.Errorf("GET %s headers mismatch (-want +got):\n%s", tt.path, diff)
			}

			var got map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("GET %s body is not a JSON object: %v", tt.path, err)
			}
			want := map[string]any{
				"issuer":                                tt.issuer,
				"authorization_endpoint":                tt.issuer + "/authorize",
				"token_endpoint":                        tt.issuer + "/token",
				"userinfo_endpoint":                     tt.issuer + "/userinfo",
				"jwks_uri":                              tt.issuer + "/jwks",
				"scopes_supported":                      []any{"openid", "profile", "email", "address", "phone"},
				"response_types_supported":              []any{"code"},
				"response_modes_supported":              []any{"query"},
				"grant_types_supported":                 []any{"authorization_code"},
				"subject_types_supported":               []any{"public"},
				"id_token_signing_alg_values_supported": []any{"RS256"},
				"token_endpoint_auth_methods_supported": []any{
					"client_secret_basic", "client_secret_post", "private_key_jwt", "none",
				},
				"token_endpoint_auth_signing_alg_values_supported": []any{"RS256", "PS256", "ES256"},
				"code_challenge_methods_supported":                 []any{"S256"},
				"claims_supported": []any{
					"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
					"name", "given_name", "family_name", "middle_name", "nickname",
					"preferred_username", "profile", "picture", "website",
					"email", "email_verified", "gender", "birthdate", "zoneinfo",
					"locale", "phone_number", "phone_number_verified", "address",
					"updated_at",
				},
				"claims_parameter_supported":                     true,
				"request_parameter_supported":                    false,
				"request_uri_parameter_supported":                false,
				"authorization_response_iss_parameter_supported": true,
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("GET %s metadata mismatch (-want +got):\n%s", tt.path, diff)
			}
		})
	}
}

// REQ-DISC-12: the document and the JWK Set are served under the issuer's
// path only, and the endpoints the document names that later tickets
// implement answer 404 until then.
func TestNotFound(t *testing.T) {
	t.Parallel()

	paths := []string{
		"/.well-known/openid-configuration",
		"/tenant/authorize",
		"/tenant/token",
		"/tenant/userinfo",
		"/jwks",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, http.NoBody)
			newHandlerWithoutDatabase(t, "https://op.example/tenant").ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Errorf("GET %s status = %d, want %d", path, rec.Code, http.StatusNotFound)
			}
		})
	}
}
