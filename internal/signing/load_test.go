package signing_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
	"github.com/palebluedot4/pulsar/internal/signing"
)

// Before the key set is loaded, nothing signs, and no token verifies, not
// even one a key of another key set signed. It cites no requirement: no
// clause in scope says what an OP does before it has keys.
func TestSignAndVerifyBeforeLoad(t *testing.T) {
	t.Parallel()

	_, token := signedBy(t, load(t, postgrestest.Open(t, postgrestest.NewDatabase(t))))
	keys := signing.New(postgrestest.Open(t, postgrestest.UnreachableURL(t)), secret)
	if _, err := keys.Active(); err == nil {
		t.Error("Active() before Load error = nil, want an error")
	}
	if _, err := keys.SignJWT("JWT", map[string]any{"iss": "https://op.example"}); err == nil {
		t.Error("SignJWT() before Load error = nil, want an error")
	}
	if _, _, ok := keys.VerifyJWT(token); ok {
		t.Error("VerifyJWT() before Load = true, want false")
	}
	if _, _, ok := keys.VerifyIDTokenHint(token); ok {
		t.Error("VerifyIDTokenHint() before Load = true, want false")
	}
}

// REQ-AT-9, REQ-LOGOUT-2: a JWT whose kid names a published key, but whose
// signature is not that key's over its header and claims, verifies neither
// as a token nor as an id_token_hint.
func TestVerifyRefusesAlteredJWT(t *testing.T) {
	t.Parallel()

	keys := load(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	_, token := signedBy(t, keys)
	parts := strings.Split(token, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("SignJWT() signature is not base64url: %v", err)
	}
	sig[0] ^= 1

	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "claims altered",
			token: parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://attacker.example"}`)) + "." + parts[2],
		},
		{
			name:  "signature altered",
			token: parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, _, ok := keys.VerifyJWT(tt.token); ok {
				t.Errorf("VerifyJWT(a JWT with its %s) = true, want false", tt.name)
			}
			if _, _, ok := keys.VerifyIDTokenHint(tt.token); ok {
				t.Errorf("VerifyIDTokenHint(a JWT with its %s) = true, want false", tt.name)
			}
		})
	}
}

// REQ-JWA-1: a stored RSA key of fewer than 2048 bits is refused when the
// key set loads, rather than signed with, and one of 2048 bits, stored as
// the key set stores one, loads. Refused too are a key that is not RSA,
// and a key stored under a kid that is not its thumbprint, which the JWK
// Set would publish under that kid; those cases cite no requirement: no
// clause in scope says how an OP stores its keys.
func TestLoadStoredKey(t *testing.T) {
	t.Parallel()

	rsa1024, err1024 := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // G403: a key too small, for Load to refuse.
	p256, errP256 := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, errRSA := rsa.GenerateKey(rand.Reader, 2048)
	other, errOther := rsa.GenerateKey(rand.Reader, 2048)
	for _, err := range []error{err1024, errP256, errRSA, errOther} {
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
	}

	tests := []struct {
		name string
		kid  string
		key  crypto.Signer
		ok   bool
	}{
		{name: "an RSA key of 2048 bits", kid: thumbprintOf(t, rsaKey.Public()), key: rsaKey, ok: true},
		{name: "an RSA key of 1024 bits", kid: thumbprintOf(t, rsa1024.Public()), key: rsa1024},
		{name: "a P-256 key", kid: thumbprintOf(t, p256.Public()), key: p256},
		{name: "a kid that is another key's thumbprint", kid: thumbprintOf(t, other.Public()), key: rsaKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pool := postgrestest.Open(t, postgrestest.NewDatabase(t))
			der, err := x509.MarshalPKCS8PrivateKey(tt.key)
			if err != nil {
				t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
			}
			storeKey(t, pool, tt.kid, der)
			err = signing.New(pool, secret).Load(t.Context())
			switch {
			case tt.ok && err != nil:
				t.Errorf("Load() with %s stored error = %v, want nil", tt.name, err)
			case !tt.ok && err == nil:
				t.Errorf("Load() with %s stored error = nil, want an error", tt.name)
			}
		})
	}
}

// A replica that starts once a key has left the JWK Set, while the key
// still verifies id_token_hints, decrypts the key's row, and refuses to
// load if the row was altered, as it does for a key in the JWK Set. It
// cites no requirement: no clause in scope says how an OP stores its keys.
func TestLoadRefusesAlteredRetiredKey(t *testing.T) {
	t.Parallel()

	databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
	synctest.Test(t, func(t *testing.T) {
		a := startReplica(t, databaseURL)
		old, _ := signedBy(t, a.KeySet)
		rotated, err := signing.New(a.pool, secret).Rotate(t.Context())
		if err != nil {
			t.Fatalf("Rotate() error = %v", err)
		}

		// The old key has left the JWK Set eleven minutes after the new
		// key's time to sign, and verifies hints for ten hours more.
		sleepUntil(rotated.SignsFrom.Add(11*time.Minute + 30*time.Second))
		if _, err := a.pool.Exec(t.Context(), "UPDATE signing_keys SET sealed_private_key = $1 WHERE kid = $2", []byte("altered"), old); err != nil {
			t.Fatalf("alter the old key's row: %v", err)
		}
		if err := signing.New(a.pool, secret).Load(t.Context()); err == nil {
			t.Error("Load() with the retired key's row altered error = nil, want an error")
		}
	})
}

// thumbprintOf returns the kid the key set gives pub: its RFC 7638
// thumbprint with SHA-256, base64url-encoded. It is computed here, not by
// the key set's own function, which takes RSA keys only, so that a P-256
// key can be stored under its thumbprint too, and so that a kid the key
// set computed some other way would show.
func thumbprintOf(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	b, err := (&jose.JSONWebKey{Key: pub}).Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("Thumbprint() error = %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// storeKey stores der, a private key in PKCS #8, in pool under kid,
// sealed as the key set seals one, signing from now.
func storeKey(t *testing.T, pool *pgxpool.Pool, kid string, der []byte) {
	t.Helper()
	sealed := signing.New(pool, secret).Seal(kid, der)
	if _, err := pool.Exec(t.Context(),
		"INSERT INTO signing_keys (kid, sealed_private_key, created_at, activates_at) VALUES ($1, $2, now(), now())",
		kid, sealed); err != nil {
		t.Fatalf("store signing key: %v", err)
	}
}

// sqlState returns the SQLSTATE of the PostgreSQL error err wraps, or ""
// if it wraps none.
func sqlState(err error) string {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return ""
	}
	return pgErr.Code
}

// databaseFailure makes PostgreSQL fail at one step of Load or Rotate, in
// the database at databaseURL (postgrestest).
type databaseFailure struct {
	name      string
	breakStep func(t *testing.T, databaseURL string)
	want      string // the SQLSTATE of the error that follows
}

// keyStorageFailures are the failures both Load and Rotate meet: a key
// that is not stored, and keys that are not read.
var keyStorageFailures = []databaseFailure{
	{
		name: "key not stored",
		breakStep: func(t *testing.T, databaseURL string) {
			t.Helper()
			postgrestest.FailOn(t, databaseURL, "INSERT", "signing_keys")
		},
		want: postgrestest.RaiseException,
	},
	{
		name: "keys not read",
		breakStep: func(t *testing.T, databaseURL string) {
			t.Helper()
			postgrestest.Hold(t, databaseURL, "LOCK TABLE signing_keys IN ACCESS EXCLUSIVE MODE")
		},
		want: postgrestest.LockNotAvailable,
	},
}

// Load fails when PostgreSQL does, and its error is PostgreSQL's, which
// the operator reads to learn why the replica did not start: not that the
// database holds no key, when the first key could not be stored or the
// keys could not be read, nor that a transaction was aborted, when the
// lock that key generation is under could not be taken. It cites no
// requirement: no clause in scope says how an OP stores its keys.
func TestLoadDatabaseFailure(t *testing.T) {
	t.Parallel()

	tests := append(slices.Clone(keyStorageFailures), databaseFailure{
		name: "key generation lock not taken",
		breakStep: func(t *testing.T, databaseURL string) {
			t.Helper()
			postgrestest.Hold(t, databaseURL, fmt.Sprintf("SELECT pg_advisory_xact_lock(%d)", signing.GenerationLockID))
		},
		want: postgrestest.LockNotAvailable,
	})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			databaseURL := postgrestest.NewDatabase(t)
			pool := postgrestest.Open(t, postgrestest.WithLockTimeout(t, databaseURL))
			tt.breakStep(t, databaseURL)
			err := signing.New(pool, secret).Load(t.Context())
			if got := sqlState(err); got != tt.want {
				t.Errorf("Load() with the %s: error = %v, want one with SQLSTATE %s", tt.name, err, tt.want)
			}
		})
	}
}
