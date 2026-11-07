// Package guessing limits online guessing of End-User passwords, which
// RFC 6749 §10.10 requires an authorization server to prevent, as ADR 0005
// decides. It counts the attempts to sign in as each End-User, and with
// each username no End-User has, in PostgreSQL, so that every replica sees
// the same count, and refuses an attempt that comes too soon after the
// last: the first five are free, and after them each must wait a second,
// then two, doubling up to fifteen minutes. A success clears the count,
// and a day without an attempt forgets it. Each replica times these by its
// own clock, so they hold as long as the replicas' clocks agree.
//
// An attempt is recorded before its password is checked, so that two
// replicas cannot both let through an attempt the count allows only one
// of, and one refused is refused before any hash runs, even if its
// password is right. So attempts made at once count as attempts made one
// after another: more than five at once at one End-User wait, even if
// each would succeed.
//
// Client secrets are not counted. The README requires each to be at least
// 256 random bits, which guessing cannot find, and a count kept per
// client_id, which is public, would let anyone hold up that Client's token
// requests.
package guessing

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palebluedot4/pulsar/internal/guessing/internal/queries"
)

// The limits, as ADR 0005 sets them from those of Keycloak and Ory
// (docs/research/login-throttling.md).
const (
	// freeAttempts is how many attempts at a Target may be made without a
	// success before the next must wait.
	freeAttempts = 5
	// firstDelay is how long the attempt after freeAttempts must wait;
	// each one after it waits twice as long as the one before.
	firstDelay = time.Second
	// maxDelay is the longest an attempt must wait.
	maxDelay = 15 * time.Minute
	// forgetAfter is how long after the last attempt at a Target its count
	// is forgotten.
	forgetAfter = 24 * time.Hour
)

// targetKeyInfo labels the key HKDF derives from PULSAR_SECRET for naming
// Targets, so that it differs from any key derived from the secret for
// another purpose.
const targetKeyInfo = "pulsar login attempt targets"

// Limiter counts the attempts at each Target in a database. It is safe
// for concurrent use.
type Limiter struct {
	db        *pgxpool.Pool
	targetKey []byte
}

// New returns a Limiter that keeps its counts in the database behind db,
// naming Targets under a key derived from secret, PULSAR_SECRET's value.
// It takes the bytes rather than a config.Secret because config depends,
// through oidc and login, on this package.
func New(db *pgxpool.Pool, secret []byte) *Limiter {
	key, err := hkdf.Key(sha256.New, secret, nil, targetKeyInfo, sha256.Size)
	if err != nil {
		panic(fmt.Sprintf("guessing: derive target key: %v", err)) // HKDF-SHA256 can derive a key of this size from any secret.
	}
	return &Limiter{db: db, targetKey: key}
}

// Target is what attempts to sign in are counted against: an End-User, or
// a username no End-User has. It holds an HMAC of its kind and name, so
// that the name is never stored, since a username may be a password typed
// into the wrong field.
type Target struct {
	mac []byte
}

// EndUser returns the Target of the End-User whose Subject is subject.
func (l *Limiter) EndUser(subject string) Target {
	return l.target("end-user", subject)
}

// Username returns the Target of a username no End-User has, so that
// attempts with it are counted as attempts with one that exists are, and
// a refusal does not tell which usernames exist.
func (l *Limiter) Username(username string) Target {
	return l.target("username", username)
}

// target returns the Target of the given kind and name. A kind holds no
// NUL byte, so the one that ends it keeps two pairs of kind and name from
// running together alike.
func (l *Limiter) target(kind, name string) Target {
	m := hmac.New(sha256.New, l.targetKey)
	m.Write([]byte(kind))
	m.Write([]byte{0})
	m.Write([]byte(name))
	return Target{mac: m.Sum(nil)}
}

// Attempt records an attempt at target, made now, and returns 0; or, if
// the attempt comes before the next may be made, records nothing and
// returns how long until it may be, rounded up to a whole second, as
// Retry-After states it.
func (l *Limiter) Attempt(ctx context.Context, target Target) (time.Duration, error) {
	now := time.Now()
	var wait time.Duration
	err := pgx.BeginFunc(ctx, l.db, func(tx pgx.Tx) error {
		q := queries.New(tx)
		// The row stays locked until the transaction ends, so that
		// attempts at one Target are counted one at a time.
		row, err := q.LockTarget(ctx, queries.LockTargetParams{Target: target.mac, Now: now})
		if err != nil {
			return err
		}
		attempts := row.Attempts
		switch {
		case !now.Before(row.DeleteAfter):
			attempts = 0
		case now.Before(row.NextAttempt):
			wait = row.NextAttempt.Sub(now)
			return nil
		}
		attempts++
		return q.RecordAttempt(ctx, queries.RecordAttemptParams{
			Target:      target.mac,
			Attempts:    attempts,
			NextAttempt: now.Add(delay(attempts)),
			DeleteAfter: now.Add(forgetAfter),
		})
	})
	if err != nil {
		return 0, fmt.Errorf("record an attempt: %w", err)
	}
	return (wait + time.Second - 1).Truncate(time.Second), nil
}

// delay returns how long the attempt after attempts attempts without a
// success must wait.
func delay(attempts int32) time.Duration {
	if attempts < freeAttempts {
		return 0
	}
	d := firstDelay
	for range attempts - freeAttempts {
		d *= 2
		if d >= maxDelay {
			return maxDelay
		}
	}
	return d
}

// Succeeded forgets the attempts at target, once one has succeeded.
func (l *Limiter) Succeeded(ctx context.Context, target Target) error {
	if err := queries.New(l.db).ForgetTarget(ctx, target.mac); err != nil {
		return fmt.Errorf("forget the attempts: %w", err)
	}
	return nil
}

// DeleteDue deletes from the database behind db the counts forgotten by
// now. Attempt treats a forgotten count as none, so a count kept past it
// is never used; deleting it only bounds how long it stays.
func DeleteDue(ctx context.Context, db *pgxpool.Pool, now time.Time) error {
	if err := queries.New(db).DeleteForgottenTargets(ctx, now); err != nil {
		return fmt.Errorf("delete forgotten login attempts: %w", err)
	}
	return nil
}
