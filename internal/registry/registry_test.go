package registry_test

import (
	"testing"

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
			"jwks": {"keys": [{"kty": "EC", "crv": "P-256",
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
