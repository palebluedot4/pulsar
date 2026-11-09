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
