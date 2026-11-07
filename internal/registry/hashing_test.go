package registry

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/crypto/argon2"
)

// hashOf returns an Argon2id PHC string for password over memory KiB, in
// one pass, so that tests run fast.
func hashOf(tb testing.TB, password string, memory uint32) string {
	tb.Helper()
	salt := make([]byte, 16)
	_, _ = rand.Read(salt) // crypto/rand.Read never returns an error.
	key := argon2.IDKey([]byte(password), salt, 1, memory, 1, 32)
	enc := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=1,p=1$%s$%s", memory, enc(salt), enc(key))
}

// REQ-OAUTH-44: a registry runs at most as many verifications at once as
// fill GOMAXPROCS times the memory of its largest hash, here a Client's,
// which bounds how fast passwords and Client secrets can be guessed. One
// that finds no room waits for it, for up to two seconds, and is then
// refused with ErrBusy, whether it is a login, a login with a username no
// End-User has, or a Client's authentication.
func TestVerificationCap(t *testing.T) {
	t.Parallel()

	const (
		password     = "correct horse battery staple"
		secret       = "s3cr3t"
		aliceMemory  = 64  // KiB
		clientMemory = 128 // KiB, the largest
	)
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()
		reg, err := Parse([]byte(`{
			"clients": [{"client_id": "rp", "token_endpoint_auth_method": "client_secret_basic",
				"client_secret_hash": "` + hashOf(t, secret, clientMemory) + `", "redirect_uris": ["https://rp.example/callback"]}],
			"end_users": [{"sub": "7c9e6679-7425-40de-944b-e07fc1f90ae7", "username": "alice",
				"password_hash": "` + hashOf(t, password, aliceMemory) + `"}]
		}`))
		if err != nil {
			t.Fatal(err)
		}
		size := int64(runtime.GOMAXPROCS(0)) * clientMemory

		// Room for exactly one of alice's verifications.
		if err := reg.hashing.Acquire(ctx, size-aliceMemory); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if _, ok, err := reg.AuthenticateEndUser(ctx, "alice", password); !ok || err != nil {
			t.Fatalf("AuthenticateEndUser(alice) with room for it = %v, %v; want true, nil", ok, err)
		}
		if waited := time.Since(start); waited != 0 {
			t.Errorf("AuthenticateEndUser(alice) with room for it waited %v, want 0", waited)
		}

		// A KiB short of it.
		if err := reg.hashing.Acquire(ctx, 1); err != nil {
			t.Fatal(err)
		}
		attempts := map[string]func() error{
			"AuthenticateEndUser(alice)": func() error {
				_, _, err := reg.AuthenticateEndUser(ctx, "alice", password)
				return err
			},
			"AuthenticateEndUser(carol)": func() error {
				_, _, err := reg.AuthenticateEndUser(ctx, "carol", password)
				return err
			},
			"AuthenticateClientSecret(rp)": func() error {
				_, _, err := reg.AuthenticateClientSecret(ctx, ClientSecretBasic, "rp", secret)
				return err
			},
		}
		for name, attempt := range attempts {
			start := time.Now()
			if err := attempt(); !errors.Is(err, ErrBusy) {
				t.Errorf("%s without room = %v, want %v", name, err, ErrBusy)
			}
			if waited := time.Since(start); waited != 2*time.Second {
				t.Errorf("%s without room waited %v, want %v", name, waited, 2*time.Second)
			}
		}

		// Room made while it waits lets it through then.
		go func() {
			time.Sleep(time.Second)
			reg.hashing.Release(1)
		}()
		start = time.Now()
		if _, ok, err := reg.AuthenticateEndUser(ctx, "alice", password); !ok || err != nil {
			t.Fatalf("AuthenticateEndUser(alice) with room made a second later = %v, %v; want true, nil", ok, err)
		}
		if waited := time.Since(start); waited != time.Second {
			t.Errorf("AuthenticateEndUser(alice) with room made a second later waited %v, want %v", waited, time.Second)
		}
	})
}
