package registry

import (
	"crypto/rand"
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
	return passwordHash{memory: memory, time: 1, threads: 1, salt: salt, key: key}.encode()
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
		if _, ok, err := reg.AuthenticateEndUser(ctx, "alice", password, nil); !ok || err != nil {
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
				_, _, err := reg.AuthenticateEndUser(ctx, "alice", password, nil)
				return err
			},
			"AuthenticateEndUser(carol)": func() error {
				_, _, err := reg.AuthenticateEndUser(ctx, "carol", password, nil)
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
		// A login refused for want of room is not admitted, and so not
		// counted.
		if _, _, err := reg.AuthenticateEndUser(ctx, "alice", password, func(*EndUser) error {
			t.Error("AuthenticateEndUser(alice) without room called admit")
			return nil
		}); !errors.Is(err, ErrBusy) {
			t.Errorf("AuthenticateEndUser(alice) without room, with admit = %v, want %v", err, ErrBusy)
		}

		// Room made while it waits lets it through then.
		go func() {
			time.Sleep(time.Second)
			reg.hashing.Release(1)
		}()
		start = time.Now()
		if _, ok, err := reg.AuthenticateEndUser(ctx, "alice", password, nil); !ok || err != nil {
			t.Fatalf("AuthenticateEndUser(alice) with room made a second later = %v, %v; want true, nil", ok, err)
		}
		if waited := time.Since(start); waited != time.Second {
			t.Errorf("AuthenticateEndUser(alice) with room made a second later waited %v, want %v", waited, time.Second)
		}
	})
}

// AuthenticateEndUser calls admit once there is room to check the
// password, with the End-User who has the username, or nil for a username
// no End-User has, and returns admit's error without checking the
// password, so that even the right one does not sign in.
func TestAuthenticateEndUserAdmit(t *testing.T) {
	t.Parallel()

	const password = "correct horse battery staple"
	reg, err := Parse([]byte(`{"end_users": [{"sub": "7c9e6679-7425-40de-944b-e07fc1f90ae7", "username": "alice",
		"password_hash": "` + hashOf(t, password, 64) + `"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	refused := errors.New("refused")
	tests := []struct {
		username    string
		admitErr    error
		wantSubject string // of the End-User admit is called with, or "" for nil
		wantOK      bool
		wantErr     error
	}{
		{username: "alice", wantSubject: "7c9e6679-7425-40de-944b-e07fc1f90ae7", wantOK: true},
		{username: "alice", admitErr: refused, wantSubject: "7c9e6679-7425-40de-944b-e07fc1f90ae7", wantErr: refused},
		{username: "carol"},
		{username: "carol", admitErr: refused, wantErr: refused},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%v", tt.username, tt.admitErr), func(t *testing.T) {
			t.Parallel()
			calls := 0
			var gotSubject string
			_, ok, err := reg.AuthenticateEndUser(t.Context(), tt.username, password, func(u *EndUser) error {
				calls++
				if u != nil {
					gotSubject = u.Subject
				}
				return tt.admitErr
			})
			if ok != tt.wantOK || !errors.Is(err, tt.wantErr) {
				t.Errorf("AuthenticateEndUser(%s) with admit returning %v = %v, %v; want %v, %v", tt.username, tt.admitErr, ok, err, tt.wantOK, tt.wantErr)
			}
			if calls != 1 || gotSubject != tt.wantSubject {
				t.Errorf("AuthenticateEndUser(%s) called admit %d times with Subject %q, want once with %q", tt.username, calls, gotSubject, tt.wantSubject)
			}
		})
	}
}
