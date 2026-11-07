package guessing_test

import (
	"bytes"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palebluedot4/pulsar/internal/guessing"
	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
)

// subject is the Subject of the End-User whose account the tests count
// attempts at.
const subject = "7c9e6679-7425-40de-944b-e07fc1f90ae7"

// newLimiter returns a Limiter on the database at databaseURL, and the
// pool it uses. Called inside a testing/synctest bubble, so that the test
// controls the clock, it opens the pool there, as signing's tests do;
// databaseURL must name an address rather than a host name.
func newLimiter(t *testing.T, databaseURL string) (*pgxpool.Pool, *guessing.Limiter) {
	t.Helper()
	pool, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatalf("pgxpool.New() error = %v", err)
	}
	t.Cleanup(pool.Close)
	return pool, guessing.New(pool, []byte("secret"))
}

// attempt makes an attempt at account and returns how long until the next
// may be made, or 0 if this one was made.
func attempt(t *testing.T, l *guessing.Limiter, account guessing.Account) time.Duration {
	t.Helper()
	wait, err := l.Attempt(t.Context(), account)
	if err != nil {
		t.Fatalf("Attempt() error = %v", err)
	}
	return wait
}

// attemptFree makes n attempts at account, each of which must be made.
func attemptFree(t *testing.T, l *guessing.Limiter, account guessing.Account, n int) {
	t.Helper()
	for i := range n {
		if got := attempt(t, l, account); got != 0 {
			t.Fatalf("Attempt() number %d = %v, want 0", i+1, got)
		}
	}
}

// REQ-OAUTH-45: five attempts are made at once; after them each must wait
// a second, then two, doubling up to fifteen minutes. One that comes
// sooner is refused, with the time left rounded up to a second, and is
// not counted.
func TestAttemptDelay(t *testing.T) {
	t.Parallel()

	databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
	synctest.Test(t, func(t *testing.T) {
		_, l := newLimiter(t, databaseURL)
		alice := l.EndUser(subject)
		attemptFree(t, l, alice, 5)
		const s = time.Second
		for _, want := range []time.Duration{s, 2 * s, 4 * s, 8 * s, 16 * s, 32 * s, 64 * s, 128 * s, 256 * s, 512 * s, 15 * time.Minute, 15 * time.Minute} {
			if got := attempt(t, l, alice); got != want {
				t.Fatalf("Attempt() at once = %v, want %v", got, want)
			}
			time.Sleep(want - time.Nanosecond)
			if got := attempt(t, l, alice); got != time.Second {
				t.Fatalf("Attempt() a nanosecond before its time = %v, want %v", got, time.Second)
			}
			time.Sleep(time.Nanosecond)
			if got := attempt(t, l, alice); got != 0 {
				t.Fatalf("Attempt() %v after the last = %v, want 0", want, got)
			}
		}
	})
}

// REQ-OAUTH-45: a success clears the count, so that the five attempts
// after it are made at once.
func TestAttemptSucceeded(t *testing.T) {
	t.Parallel()

	databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
	synctest.Test(t, func(t *testing.T) {
		_, l := newLimiter(t, databaseURL)
		alice := l.EndUser(subject)
		attemptFree(t, l, alice, 5)
		if err := l.Succeeded(t.Context(), alice); err != nil {
			t.Fatalf("Succeeded() error = %v", err)
		}
		attemptFree(t, l, alice, 5)
		if got := attempt(t, l, alice); got != time.Second {
			t.Errorf("Attempt() after five more = %v, want %v", got, time.Second)
		}
	})
}

// REQ-OAUTH-45: the count is forgotten a day after the last attempt, and
// not before.
func TestAttemptForgotten(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		sleep time.Duration
		want  time.Duration // the wait for the attempt after the one made then
	}{
		{name: "a day later", sleep: 24 * time.Hour, want: 0},
		{name: "a nanosecond before a day", sleep: 24*time.Hour - time.Nanosecond, want: 2 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
			synctest.Test(t, func(t *testing.T) {
				_, l := newLimiter(t, databaseURL)
				alice := l.EndUser(subject)
				attemptFree(t, l, alice, 5)
				time.Sleep(tt.sleep)
				attemptFree(t, l, alice, 1)
				if got := attempt(t, l, alice); got != tt.want {
					t.Errorf("Attempt() %v after five, and one then = %v, want %v", tt.sleep, got, tt.want)
				}
			})
		})
	}
}

// REQ-OAUTH-45: each account has a count of its own: an End-User's, a
// username's, and each under the secret of its Limiter.
func TestAttemptAccounts(t *testing.T) {
	t.Parallel()

	databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
	synctest.Test(t, func(t *testing.T) {
		pool, l := newLimiter(t, databaseURL)
		attemptFree(t, l, l.EndUser(subject), 5)
		if got := attempt(t, l, l.EndUser(subject)); got != time.Second {
			t.Fatalf("Attempt() at the End-User after five = %v, want %v", got, time.Second)
		}
		other := guessing.New(pool, []byte("another secret"))
		for name, account := range map[string]guessing.Account{
			"the username alike":                l.Username(subject),
			"another End-User":                  l.EndUser("0b5c3c62-1f3e-4f2b-9f43-8c1d2e3f4a5b"),
			"the End-User under another secret": other.EndUser(subject),
			"the username under another secret": other.Username(subject),
		} {
			if got := attempt(t, l, account); got != 0 {
				t.Errorf("Attempt() at %s = %v, want 0", name, got)
			}
		}
	})
}

// REQ-OAUTH-45: attempts made at once are counted one at a time, so that
// no more get through than made one after another would.
func TestAttemptsAtOnce(t *testing.T) {
	t.Parallel()

	databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
	synctest.Test(t, func(t *testing.T) {
		_, l := newLimiter(t, databaseURL)
		alice := l.EndUser(subject)
		attemptFree(t, l, alice, 4)
		var (
			mu    sync.Mutex
			waits = map[time.Duration]int{}
			wg    sync.WaitGroup
		)
		for range 10 {
			wg.Go(func() {
				wait, err := l.Attempt(t.Context(), alice)
				if err != nil {
					t.Errorf("Attempt() error = %v", err)
					return
				}
				mu.Lock()
				waits[wait]++
				mu.Unlock()
			})
		}
		wg.Wait()
		want := map[time.Duration]int{0: 1, time.Second: 9}
		if diff := cmp.Diff(want, waits); diff != "" {
			t.Errorf("waits of 10 attempts at once after 4 mismatch (-want +got):\n%s", diff)
		}
	})
}

// What a username's attempts are counted against is stored as an HMAC,
// never as typed, since a username may be a password typed into the
// wrong field.
func TestAttemptStoresNoUsername(t *testing.T) {
	t.Parallel()

	databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
	synctest.Test(t, func(t *testing.T) {
		pool, l := newLimiter(t, databaseURL)
		const typed = "correct horse battery staple"
		attemptFree(t, l, l.Username(typed), 1)
		rows, err := pool.Query(t.Context(), "SELECT account FROM login_attempts")
		if err != nil {
			t.Fatal(err)
		}
		accounts, err := pgx.CollectRows(rows, pgx.RowTo[[]byte])
		if err != nil {
			t.Fatal(err)
		}
		if len(accounts) != 1 {
			t.Fatalf("login_attempts has %d rows, want 1", len(accounts))
		}
		if got := accounts[0]; len(got) != 32 || bytes.Contains(got, []byte(typed)) {
			t.Errorf("login_attempts.account = %q, want a 32-byte HMAC", got)
		}
	})
}
