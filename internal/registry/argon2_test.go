package registry

import (
	"crypto/rand"
	"encoding/base64"
	"net/url"
	"testing"
	"testing/cryptotest"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/argon2"
)

// REQ-OAUTH-21, REQ-OAUTH-44: NewClientSecret's secret is the first 256
// bits read from crypto/rand, in unpadded base64url, which form-encoding
// leaves as it is. Its hash is an Argon2id hash of the secret at OWASP's
// minimum of 19 MiB over two passes in one lane, with the next 16 bytes
// as its salt and a 32-byte tag, in the PHC string format the registry
// parses.
func TestNewClientSecret(t *testing.T) { //nolint:paralleltest // cryptotest.SetGlobalRandom affects the whole process.
	cryptotest.SetGlobalRandom(t, 1)
	random := make([]byte, 32+16)
	_, _ = rand.Read(random) // crypto/rand.Read never returns an error.
	cryptotest.SetGlobalRandom(t, 1)

	secret, hash := NewClientSecret()

	if want := base64.RawURLEncoding.EncodeToString(random[:32]); secret != want {
		t.Errorf("NewClientSecret() secret = %q, want %q", secret, want)
	}
	if escaped := url.QueryEscape(secret); escaped != secret {
		t.Errorf("url.QueryEscape(NewClientSecret() secret) = %q, want it unchanged, %q", escaped, secret)
	}
	got, err := parsePasswordHash(hash)
	if err != nil {
		t.Fatalf("parsePasswordHash(NewClientSecret() hash) = %v, want nil", err)
	}
	salt := random[32:]
	want := passwordHash{
		memory:  19456,
		time:    2,
		threads: 1,
		salt:    salt,
		key:     argon2.IDKey([]byte(secret), salt, 2, 19456, 1, 32),
	}
	if diff := cmp.Diff(want, got, cmp.AllowUnexported(passwordHash{})); diff != "" {
		t.Errorf("parsePasswordHash(NewClientSecret() hash) mismatch (-want +got):\n%s", diff)
	}
}

// parsePasswordHash accepts a hash at each limit RFC 9106 §3.1 sets on the
// inputs a PHC string carries, m of at least 8p KiB, a salt of at least 8
// bytes and a tag of at least 4, and at pulsar's own, m of at most 2 GiB,
// t and m that fit in 32 bits and p in 8, as x/crypto/argon2 takes them;
// and refuses one past each. It cites no requirement: RFC 9106 is not among
// the specifications in scope.
func TestParsePasswordHashLimits(t *testing.T) {
	t.Parallel()

	b64 := func(n int) string { return base64.RawStdEncoding.EncodeToString(make([]byte, n)) }
	phc := func(params string, salt, key int) string {
		return "$argon2id$v=19$" + params + "$" + b64(salt) + "$" + b64(key)
	}
	tests := []struct {
		name string
		hash string
		ok   bool
	}{
		{name: "m of 8p", hash: phc("m=8,t=1,p=1", 16, 32), ok: true},
		{name: "m of 8p for p of 2", hash: phc("m=16,t=1,p=2", 16, 32), ok: true},
		{name: "m below 8p for p of 2", hash: phc("m=15,t=1,p=2", 16, 32)},
		{name: "m of 2 GiB", hash: phc("m=2097152,t=1,p=1", 16, 32), ok: true},
		{name: "m above 2 GiB", hash: phc("m=2097153,t=1,p=1", 16, 32)},
		{name: "t of 2^32-1", hash: phc("m=8,t=4294967295,p=1", 16, 32), ok: true},
		{name: "t of 2^32", hash: phc("m=8,t=4294967296,p=1", 16, 32)},
		{name: "p of 255", hash: phc("m=2040,t=1,p=255", 16, 32), ok: true},
		{name: "p of 256", hash: phc("m=2048,t=1,p=256", 16, 32)},
		{name: "salt of 8 bytes", hash: phc("m=8,t=1,p=1", 8, 32), ok: true},
		{name: "salt of 7 bytes", hash: phc("m=8,t=1,p=1", 7, 32)},
		{name: "tag of 4 bytes", hash: phc("m=8,t=1,p=1", 16, 4), ok: true},
		{name: "tag of 3 bytes", hash: phc("m=8,t=1,p=1", 16, 3)},
		{name: "tag with a character outside base64", hash: phc("m=8,t=1,p=1", 16, 32) + "!"},
		{name: "parameters without names", hash: phc("8,1,1", 16, 32)},
		{name: "text before the first $", hash: "x" + phc("m=8,t=1,p=1", 16, 32)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := parsePasswordHash(tt.hash)
			switch {
			case tt.ok && err != nil:
				t.Errorf("parsePasswordHash(%q) error = %v, want nil", tt.hash, err)
			case !tt.ok && err == nil:
				t.Errorf("parsePasswordHash(%q) error = nil, want an error", tt.hash)
			}
		})
	}
}
