package registry_test

import (
	"encoding/json/v2"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/palebluedot4/pulsar/internal/registry"
)

// FuzzParse feeds the registry parser arbitrary input. The file is written
// by an operator, but it is parsed before anything else runs, so a panic
// on a malformed file would end pulsar without saying what is wrong.
// Whatever the input, Parse returns either a registry or an error, and
// never both nor neither.
func FuzzParse(f *testing.F) {
	const hash = "$argon2id$v=19$m=64,t=1,p=1$cHVsc2FyLXRlc3Qtc2FsdA$uyPucYpBTL3QggLzn0NmC8SoC4Vzjt3c7gsjLiRHGWc"
	seeds := []string{
		`{}`,
		`{"clients": [], "end_users": []}`,
		`{"clients": [{"client_id": "rp", "token_endpoint_auth_method": "client_secret_basic",
			"client_secret_hash": "` + hash + `", "redirect_uris": ["https://rp.example/callback"]}]}`,
		`{"clients": [{"client_id": "native", "token_endpoint_auth_method": "none",
			"redirect_uris": ["com.example.app:/oauth2redirect"]}]}`,
		`{"clients": [{"client_id": "jwt", "token_endpoint_auth_method": "private_key_jwt",
			"jwks": {"keys": [{"kty": "EC", "crv": "P-256", "alg": "ES256",
				"x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
				"y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]},
			"redirect_uris": ["https://rp.example/callback"]}]}`,
		`{"end_users": [{"sub": "7c9e6679-7425-40de-944b-e07fc1f90ae7", "username": "alice",
			"password_hash": "` + hash + `",
			"claims": {"name": "Alice", "email_verified": true, "address": {"country": "NZ"}, "updated_at": 1700000000}}]}`,
		`{"end_users": [{"sub": "7c9e6679-7425-40de-944b-e07fc1f90ae7", "username": "alice",
			"password_hash": "$argon2id$v=19$m=064,t=1,p=1$c2FsdHNhbHQ$aGFzaA"}]}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		reg, err := registry.Parse(data)
		if (reg == nil) == (err == nil) {
			t.Errorf("Parse(%q) = %v, %v; want a registry or an error", data, reg, err)
		}
	})
}

// TestClientOrigins checks the origins derived from a Client's redirect
// URIs, which browsers serialize with the scheme and host in lowercase and
// without the scheme's default port (RFC 6454 §6.1).
func TestClientOrigins(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		redirectURIs []string
		want         []string
	}{
		{name: "https", redirectURIs: []string{"https://spa.example/callback"}, want: []string{"https://spa.example"}},
		{name: "explicit port", redirectURIs: []string{"https://spa.example:8443/cb"}, want: []string{"https://spa.example:8443"}},
		{name: "default port of https", redirectURIs: []string{"https://spa.example:443/cb"}, want: []string{"https://spa.example"}},
		{name: "default port of http", redirectURIs: []string{"http://localhost:80/cb"}, want: []string{"http://localhost"}},
		{name: "http on another port", redirectURIs: []string{"http://localhost:8080/cb"}, want: []string{"http://localhost:8080"}},
		{name: "uppercase", redirectURIs: []string{"HTTPS://SPA.Example/cb"}, want: []string{"https://spa.example"}},
		{name: "IPv6 literal", redirectURIs: []string{"http://[::1]:3000/cb"}, want: []string{"http://[::1]:3000"}},
		{name: "IPv6 literal, uncompressed", redirectURIs: []string{"http://[0:0:0:0:0:0:0:1]:3000/cb"}, want: []string{"http://[::1]:3000"}},
		{name: "IPv6 literal, uppercase", redirectURIs: []string{"https://[2001:DB8::1]/cb"}, want: []string{"https://[2001:db8::1]"}},
		{name: "IPv4 literal", redirectURIs: []string{"http://127.0.0.1:8080/cb"}, want: []string{"http://127.0.0.1:8080"}},
		{name: "port with a leading zero", redirectURIs: []string{"https://spa.example:08443/cb"}, want: []string{"https://spa.example:8443"}},
		{name: "default port with a leading zero", redirectURIs: []string{"https://spa.example:0443/cb"}, want: []string{"https://spa.example"}},
		{name: "query", redirectURIs: []string{"https://spa.example/cb?tenant=a"}, want: []string{"https://spa.example"}},
		{name: "userinfo", redirectURIs: []string{"https://user@spa.example/cb"}, want: []string{"https://spa.example"}},
		{
			name:         "one origin for two redirect URIs",
			redirectURIs: []string{"https://spa.example/a", "https://spa.example/b", "https://other.example/cb"},
			want:         []string{"https://spa.example", "https://other.example"},
		},
		// A native Client's redirect URI has no origin a browser would send.
		{name: "custom scheme", redirectURIs: []string{"com.example.app:/oauth2redirect"}, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			uris, err := json.Marshal(tt.redirectURIs)
			if err != nil {
				t.Fatal(err)
			}
			reg, err := registry.Parse([]byte(`{"clients": [{"client_id": "spa", "token_endpoint_auth_method": "none", "redirect_uris": ` + string(uris) + `}]}`))
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			c, ok := reg.Client("spa")
			if !ok {
				t.Fatal(`Client("spa") not found`)
			}
			if diff := cmp.Diff(tt.want, c.Origins); diff != "" {
				t.Errorf("Client(%q).Origins for redirect_uris %q mismatch (-want +got):\n%s", "spa", tt.redirectURIs, diff)
			}
		})
	}
}
