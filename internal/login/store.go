package login

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/palebluedot4/pulsar/internal/login/internal/queries"
)

// store keeps scs's sessions in PostgreSQL, as the scs.CtxStore that scs
// calls in preference to its Store methods.
//
// It stands in for scs's own pgxstore, which compares each session's
// expiry with the database's current_timestamp. pulsar computes every
// time in Go and passes it to SQL (#11), so that testing/synctest can
// move the clock past a Login Session's idle and absolute limits; the
// database's clock would ignore it. pgxstore also deletes ended sessions
// from a goroutine of its own; here the login handler does, at each
// login.
type store struct {
	queries *queries.Queries
}

// FindCtx returns the data of the session whose token is token, if it has
// not ended by pulsar's clock.
func (s *store) FindCtx(ctx context.Context, token string) ([]byte, bool, error) {
	data, err := s.queries.FindLoginSession(ctx, queries.FindLoginSessionParams{Token: token, Now: time.Now()})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

// CommitCtx stores a session's data, replacing any stored under token.
func (s *store) CommitCtx(ctx context.Context, token string, data []byte, expiry time.Time) error {
	return s.queries.CommitLoginSession(ctx, queries.CommitLoginSessionParams{Token: token, Data: data, Expiry: expiry})
}

// DeleteCtx deletes a session, if it exists.
func (s *store) DeleteCtx(ctx context.Context, token string) error {
	return s.queries.DeleteLoginSession(ctx, token)
}

// deleteEnded deletes every Login Session that has ended by pulsar's clock.
func (s *store) deleteEnded(ctx context.Context) error {
	return s.queries.DeleteEndedLoginSessions(ctx, time.Now())
}

// Find, Commit and Delete complete scs.Store, which scs.CtxStore embeds.
// scs never calls them, since store has the methods that take a context.

func (s *store) Find(token string) ([]byte, bool, error) {
	return s.FindCtx(context.Background(), token)
}

func (s *store) Commit(token string, data []byte, expiry time.Time) error {
	return s.CommitCtx(context.Background(), token, data, expiry)
}

func (s *store) Delete(token string) error {
	return s.DeleteCtx(context.Background(), token)
}
