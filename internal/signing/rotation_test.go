package signing_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palebluedot4/pulsar/internal/config"
	"github.com/palebluedot4/pulsar/internal/oidc"
	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
	"github.com/palebluedot4/pulsar/internal/signing"
)

// replica is a key set loaded inside a synctest bubble and reloading
// every interval until the test ends.
type replica struct {
	*signing.KeySet
	pool *pgxpool.Pool
}

// startReplica opens a pool on databaseURL inside the calling synctest
// bubble, loads a key set from it and reloads it until the test ends.
//
// The pool is opened inside the bubble, so that its connections and
// timers belong to it, on an address rather than a host name, so that it
// never touches net's resolver (see postgrestest.ResolveHost). Requests go
// to handlers directly: a server's listener, blocked in the network, would
// keep the bubble's clock from advancing.
func startReplica(t *testing.T, databaseURL string) replica {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("pgxpool.New() error = %v", err)
	}
	keys := load(t, pool)
	reloading := make(chan struct{})
	go func() {
		defer close(reloading)
		keys.Run(ctx, slog.New(slog.NewTextHandler(t.Output(), nil)))
	}()
	t.Cleanup(func() {
		cancel()
		<-reloading
		pool.Close()
	})
	return replica{KeySet: keys, pool: pool}
}

// signedBy signs a JWT with keys and returns its header's kid and the JWT,
// after checking that the JWT verifies against the JWK Set that keys
// publishes.
func signedBy(t *testing.T, keys *signing.KeySet) (kid, token string) {
	t.Helper()
	token, err := keys.SignJWT("JWT", map[string]any{"iss": "https://op.example"})
	if err != nil {
		t.Fatalf("SignJWT() error = %v", err)
	}
	jws, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("ParseSignedCompact() error = %v", err)
	}
	kid = jws.Signatures[0].Header.KeyID
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(getJWKS(t, keys).Body.Bytes(), &set); err != nil {
		t.Fatalf("GET /jwks body: %v", err)
	}
	published := set.Key(kid)
	if len(published) != 1 {
		t.Fatalf("SignJWT() signed with kid %q, which GET /jwks publishes %d times, want once", kid, len(published))
	}
	if _, err := jws.Verify(published[0]); err != nil {
		t.Errorf("SignJWT() result does not verify against the published key %q: %v", kid, err)
	}
	return kid, token
}

// REQ-JWK-2, REQ-CORE-50: a rotated key is published at the next reload,
// under a kid of its own, and signs only once the activation delay, one
// reload interval plus the JWK Set's cache lifetime, has passed, so that
// every replica and every cached JWK Set has it before any token names
// it. Until then the old key signs; every token names a published key.
func TestRotateActivatesAfterDelay(t *testing.T) {
	t.Parallel()

	databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
	synctest.Test(t, func(t *testing.T) {
		r := startReplica(t, databaseURL)
		old, _ := signedBy(t, r.KeySet)

		rotated, err := signing.New(r.pool, secret).Rotate(t.Context())
		if err != nil {
			t.Fatalf("Rotate() error = %v", err)
		}
		if rotated.KID == old {
			t.Fatalf("Rotate() kid = %q, the old key's; want a new one", rotated.KID)
		}
		if got, want := rotated.SignsFrom, time.Now().Add(signing.ActivationDelay); !got.Equal(want) {
			t.Errorf("Rotate() SignsFrom = %v, want %v", got, want)
		}
		if got, want := signing.ActivationDelay, 2*time.Minute; got != want {
			t.Errorf("ActivationDelay = %v, want %v: one reload interval plus the JWK Set's max-age", got, want)
		}

		both := slices.Sorted(slices.Values([]string{old, rotated.KID}))
		time.Sleep(signing.ReloadInterval)
		synctest.Wait()
		if diff := cmp.Diff(both, sortedKids(decodeJWKS(t, getJWKS(t, r.KeySet)))); diff != "" {
			t.Errorf("GET /jwks one reload interval after Rotate() kids mismatch (-want +got):\n%s", diff)
		}

		time.Sleep(signing.ActivationDelay - signing.ReloadInterval - time.Nanosecond)
		synctest.Wait()
		if got, _ := signedBy(t, r.KeySet); got != old {
			t.Errorf("SignJWT() just before the activation delay signed with %q, want the old key %q", got, old)
		}
		if diff := cmp.Diff(both, sortedKids(decodeJWKS(t, getJWKS(t, r.KeySet)))); diff != "" {
			t.Errorf("GET /jwks just before the activation delay kids mismatch (-want +got):\n%s", diff)
		}

		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if got, _ := signedBy(t, r.KeySet); got != rotated.KID {
			t.Errorf("SignJWT() after the activation delay signed with %q, want the rotated key %q", got, rotated.KID)
		}
		if diff := cmp.Diff(both, sortedKids(decodeJWKS(t, getJWKS(t, r.KeySet)))); diff != "" {
			t.Errorf("GET /jwks after the activation delay kids mismatch (-want +got):\n%s", diff)
		}
	})
}

// REQ-CORE-51: a key that a rotation replaced stays published, and its
// tokens verify, until every token it signed has expired; then it leaves
// the JWK Set and its tokens no longer verify.
//
// A second replica reloads 1ns before the new key's time to sign and next
// a reload interval later. It signs the old key's last token 1ns before
// that time, and switches to the new key when the time comes, not at its
// next reload: a replica whose reload then fails or is slow does not go on
// signing with a key the others are about to retire.
func TestRotatedOutKeyLeavesJWKSAfterItsTokensExpire(t *testing.T) {
	t.Parallel()

	databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		a := startReplica(t, databaseURL)
		old, _ := signedBy(t, a.KeySet)
		rotated, err := signing.New(a.pool, secret).Rotate(t.Context())
		if err != nil {
			t.Fatalf("Rotate() error = %v", err)
		}

		// b reloads every minute from 1ns before the first minute: at 1ns
		// before two minutes, the new key's time to sign, and next at 1ns
		// before three.
		time.Sleep(signing.ReloadInterval - time.Nanosecond)
		b := startReplica(t, databaseURL)

		sleepUntil(start.Add(2*time.Minute - time.Nanosecond))
		kid, last := signedBy(t, b.KeySet)
		if kid != old {
			t.Fatalf("SignJWT() on the second replica 1ns before the new key's time signed with %q, want the old key %q", kid, old)
		}
		lastExpiry := time.Now().Add(oidc.TokenLifetime)
		sleepUntil(start.Add(2 * time.Minute))
		if kid, _ := signedBy(t, b.KeySet); kid != rotated.KID {
			t.Errorf("SignJWT() on the second replica at the new key's time, before its next reload, signed with %q, want the rotated key %q", kid, rotated.KID)
		}

		// Two minutes to the new key's time to sign, one reload interval,
		// and the ten-minute token lifetime.
		gone := start.Add(13 * time.Minute)
		sleepUntil(gone.Add(-time.Nanosecond))
		if !slices.Contains(sortedKids(decodeJWKS(t, getJWKS(t, a.KeySet))), old) {
			t.Errorf("GET /jwks 1ns before %v after Rotate() has no old key %q, want it still published", gone.Sub(start), old)
		}
		if _, _, ok := a.VerifyJWT(last); !ok {
			t.Errorf("VerifyJWT(the old key's last token) 1ns before %v after Rotate() = false, want true", gone.Sub(start))
		}

		sleepUntil(gone)
		if time.Now().Before(lastExpiry) {
			t.Errorf("GET /jwks %v after Rotate() has dropped the old key, want it kept until its last token expires, %v after Rotate()", time.Since(start), lastExpiry.Sub(start))
		}
		if diff := cmp.Diff([]string{rotated.KID}, sortedKids(decodeJWKS(t, getJWKS(t, a.KeySet)))); diff != "" {
			t.Errorf("GET /jwks %v after Rotate() kids mismatch (-want +got):\n%s", gone.Sub(start), diff)
		}
		if _, _, ok := a.VerifyJWT(last); ok {
			t.Errorf("VerifyJWT(the old key's last token) %v after Rotate() = true, want false", gone.Sub(start))
		}
		if kid, _ := signedBy(t, a.KeySet); kid != rotated.KID {
			t.Errorf("SignJWT() %v after Rotate() signed with %q, want the rotated key %q", gone.Sub(start), kid, rotated.KID)
		}

		// b reloads 1ns before a, at 1ns before 13 minutes, so its first
		// reload from 13 minutes is at 1ns before 14.
		sleepUntil(start.Add(14*time.Minute - time.Nanosecond))
		if diff := cmp.Diff([]string{rotated.KID}, sortedKids(decodeJWKS(t, getJWKS(t, b.KeySet)))); diff != "" {
			t.Errorf("GET /jwks on the second replica at its first reload from %v after Rotate() kids mismatch (-want +got):\n%s", gone.Sub(start), diff)
		}
	})
}

// REQ-LOGOUT-3, REQ-CORE-51: a key that has left the JWK Set still
// verifies an id_token_hint it signed, and nothing else, until a Login
// Session's ten-hour lifetime plus a reload interval has passed since the
// next key started signing: on the replica that published it, and on one
// that starts once it has left. It signs nothing, and never returns to the
// JWK Set. Its hints are refused from that time, by each replica's clock,
// whether or not a reload falls then.
func TestRetiredKeyVerifiesOnlyIDTokenHints(t *testing.T) {
	t.Parallel()

	databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
	synctest.Test(t, func(t *testing.T) {
		a := startReplica(t, databaseURL)
		_, token := signedBy(t, a.KeySet)
		rotated, err := signing.New(a.pool, secret).Rotate(t.Context())
		if err != nil {
			t.Fatalf("Rotate() error = %v", err)
		}

		// The old key leaves the JWK Set eleven minutes after the new key's
		// time to sign, at a's reload then. b starts half a reload interval
		// later, so that it reloads half an interval apart from a.
		sleepUntil(rotated.SignsFrom.Add(11*time.Minute + 30*time.Second))
		b := startReplica(t, databaseURL)
		check := func(when string, wantHint bool) {
			t.Helper()
			for name, r := range map[string]replica{"first replica": a, "replica started later": b} {
				if _, _, ok := r.VerifyIDTokenHint(token); ok != wantHint {
					t.Errorf("%s: VerifyIDTokenHint(the old key's token) on the %s = %t, want %t", when, name, ok, wantHint)
				}
				if _, _, ok := r.VerifyJWT(token); ok {
					t.Errorf("%s: VerifyJWT(the old key's token) on the %s = true, want false", when, name)
				}
				if diff := cmp.Diff([]string{rotated.KID}, sortedKids(decodeJWKS(t, getJWKS(t, r.KeySet)))); diff != "" {
					t.Errorf("%s: GET /jwks on the %s kids mismatch (-want +got):\n%s", when, name, diff)
				}
				if kid, _ := signedBy(t, r.KeySet); kid != rotated.KID {
					t.Errorf("%s: SignJWT() on the %s signed with %q, want the rotated key %q", when, name, kid, rotated.KID)
				}
			}
		}
		check("once the old key has left the JWK Set", true)

		// The Login Session's lifetime and one reload interval after the new
		// key's time to sign: a reloads then, and b half an interval later.
		refusedFrom := rotated.SignsFrom.Add(10*time.Hour + time.Minute)
		sleepUntil(refusedFrom.Add(-time.Nanosecond))
		check("1ns before the old key's hints are refused", true)
		sleepUntil(refusedFrom)
		check("when the old key's hints are refused", false)
		sleepUntil(refusedFrom.Add(time.Hour))
		check("an hour later", false)
	})
}

// sleepUntil sleeps until t, by the bubble's clock, and waits for the
// bubble's goroutines to block.
func sleepUntil(t time.Time) {
	time.Sleep(time.Until(t))
	synctest.Wait()
}

// A rotation under a secret other than the one the keys are stored under
// is refused, and stores nothing; otherwise it would store a key that no
// replica can decrypt, and every replica would fail to load. A rotation
// in a database with no key is refused too. It cites no requirement: no
// clause in scope says how an OP stores its keys.
func TestRotateRefuses(t *testing.T) {
	t.Parallel()

	t.Run("another secret", func(t *testing.T) {
		t.Parallel()
		pool := postgrestest.Open(t, postgrestest.NewDatabase(t))
		load(t, pool)
		if _, err := signing.New(pool, config.Secret{4, 5, 6}).Rotate(t.Context()); err == nil {
			t.Fatal("Rotate() under another secret error = nil, want an error")
		}
		// A key stored under the other secret would make this fail.
		if err := signing.New(pool, secret).Load(t.Context()); err != nil {
			t.Errorf("Load() after the refused Rotate() error = %v, want nil", err)
		}
	})
	t.Run("no key", func(t *testing.T) {
		t.Parallel()
		pool := postgrestest.Open(t, postgrestest.NewDatabase(t))
		if _, err := signing.New(pool, secret).Rotate(t.Context()); err == nil {
			t.Fatal("Rotate() with no key stored error = nil, want an error")
		}
	})
}

// A key stored by a replica of a release before rotation, which knows no
// activates_at, signs from when it was generated: such a replica may store
// the first key while a rolling deploy runs. The test clears the column of
// a stored key, as that replica's insert would leave it.
func TestLoadKeyOfEarlierRelease(t *testing.T) {
	t.Parallel()

	pool := postgrestest.Open(t, postgrestest.NewDatabase(t))
	stored, err := load(t, pool).Active()
	if err != nil {
		t.Fatalf("Active() error = %v", err)
	}
	if _, err := pool.Exec(t.Context(), "UPDATE signing_keys SET activates_at = NULL"); err != nil {
		t.Fatalf("clear activates_at: %v", err)
	}
	if kid, _ := signedBy(t, load(t, pool)); kid != stored.KID {
		t.Errorf("SignJWT() with a key of an earlier release signed with %q, want %q", kid, stored.KID)
	}
}
