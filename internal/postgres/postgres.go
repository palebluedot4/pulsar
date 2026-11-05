// Package postgres holds pulsar's PostgreSQL infrastructure: the schema and
// its migrations. Queries belong to the domain packages that run them.
//
// Every time one of pulsar's own queries compares or stores is computed in
// Go and passed as a parameter; none calls now() or another clock function
// of the database, so tests control time with testing/synctest. goose's
// version table is goose's: it records when each migration was applied with
// a DEFAULT now(), which nothing in pulsar reads.
package postgres

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

//go:embed migrations/*.sql
var migrations embed.FS

// LockRetryInterval is how often a replica that finds the migration lock
// held tries it again. goose's default is five seconds, which would delay
// every replica that starts behind another by that much.
const LockRetryInterval = time.Second

// lockTimeout is how long a replica waits for the migration lock before it
// gives up: five minutes, goose's default.
const lockTimeout = 5 * time.Minute

// Migrations returns the embedded migration files.
func Migrations() fs.FS {
	sub, err := fs.Sub(migrations, "migrations")
	if err != nil {
		panic(err) // The directory is embedded; fs.Sub cannot fail on it.
	}
	return sub
}

// Migrate applies every embedded migration that the database behind pool
// has not yet applied, and returns how many it applied.
//
// It holds a PostgreSQL session-level advisory lock while it runs, so that
// replicas starting together migrate once: the first applies the pending
// migrations and the others wait, then find none pending and apply none.
func Migrate(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	locker, err := lock.NewPostgresSessionLocker(lock.WithLockTimeout(
		uint64(LockRetryInterval/time.Second),
		uint64(lockTimeout/LockRetryInterval),
	))
	if err != nil {
		return 0, fmt.Errorf("create migration lock: %w", err)
	}
	db := stdlib.OpenDBFromPool(pool)
	defer db.Close() //nolint:errcheck // Closing this *sql.DB leaves the pool open and cannot fail.

	provider, err := goose.NewProvider(goose.DialectPostgres, db, Migrations(),
		goose.WithSessionLocker(locker),
		goose.WithDisableGlobalRegistry(true),
	)
	if err != nil {
		return 0, fmt.Errorf("load migrations: %w", err)
	}
	results, err := provider.Up(ctx)
	if err != nil {
		return 0, fmt.Errorf("apply migrations: %w", err)
	}
	return len(results), nil
}
