package oidc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palebluedot4/pulsar/internal/oidc/internal/queries"
)

// DeleteDue deletes from the database behind db the records due at now:
// the authorization codes due, the access tokens and client assertions
// expired, and the Refresh Token Families ended, with their refresh
// tokens. Each row records when it is due: a code at its expiry, unless it
// is redeemed and the tokens issued from it may still be revoked, so that
// a second redemption still revokes them (RFC 6749 §4.1.2).
//
// Every endpoint checks a record's expiry itself, so a record kept past
// it is never accepted; deleting it only bounds how long it stays. Each
// deletion is attempted even if another fails, and their errors are
// returned joined.
func DeleteDue(ctx context.Context, db *pgxpool.Pool, now time.Time) error {
	q := queries.New(db)
	deletions := []struct {
		what   string
		delete func(context.Context, time.Time) error
	}{
		{"authorization codes due", q.DeleteDueAuthorizationCodes},
		{"expired access tokens", q.DeleteExpiredAccessTokens},
		{"ended refresh token families", q.DeleteEndedRefreshTokenFamilies},
		{"expired client assertions", q.DeleteExpiredClientAssertions},
	}
	var errs []error
	for _, d := range deletions {
		if err := d.delete(ctx, now); err != nil {
			errs = append(errs, fmt.Errorf("delete %s: %w", d.what, err))
		}
	}
	return errors.Join(errs...)
}
