// Package postgrestest gives each test a PostgreSQL database of its own.
//
// The server is named by PULSAR_TEST_DATABASE_URL, a postgres:// URL for a
// role that may create databases. A test that asks for a database while it
// is unset fails rather than skips, so a gate run without PostgreSQL cannot
// pass by testing less.
//
// A migrated database is cloned from a template, created once per set of
// migrations and named by their content's hash. Test binaries running in
// parallel, or worktrees with different migrations, therefore never share a
// database or a stale template. Each test's database is dropped when the
// test ends; templates are kept for the next run (docs/harness.md says how
// to drop them).
package postgrestest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palebluedot4/pulsar/internal/postgres"
)

const envURL = "PULSAR_TEST_DATABASE_URL"

// templateLockID is the advisory lock, taken on the server's maintenance
// database, under which a template is built. Its value is arbitrary.
const templateLockID int64 = 0x70756c736172 // "pulsar"

// setupTimeout bounds creating a template or a database.
const setupTimeout = time.Minute

// NewDatabase creates a database with every migration applied, for the test
// alone, and returns its URL. The database is dropped when the test ends.
func NewDatabase(tb testing.TB) string {
	tb.Helper()
	server := serverURL(tb)
	tmpl, err := template(server)
	if err != nil {
		tb.Fatalf("postgrestest: template database: %v", err)
	}
	return create(tb, server, tmpl)
}

// NewEmptyDatabase creates a database with no migration applied, for tests
// of migration itself, and returns its URL. The database is dropped when the
// test ends.
func NewEmptyDatabase(tb testing.TB) string {
	tb.Helper()
	return create(tb, serverURL(tb), "template0")
}

// Open returns a pool for databaseURL, closed when the test ends. Like
// [pgxpool.New], it does not connect until the pool is first used.
func Open(tb testing.TB, databaseURL string) *pgxpool.Pool {
	tb.Helper()
	pool, err := pgxpool.New(tb.Context(), databaseURL)
	if err != nil {
		tb.Fatalf("postgrestest: open pool: %v", err)
	}
	tb.Cleanup(pool.Close)
	return pool
}

// ResolveHost returns databaseURL with its host name replaced by the first
// of its IP addresses that accepts a TCP connection on the URL's port.
//
// A pool for the result never calls net's resolver, so it can be opened
// inside a testing/synctest bubble: the resolver keeps process-wide state
// that, created inside a bubble, belongs to it, and a parallel test that
// resolves a name afterwards crashes the test binary. Call ResolveHost
// outside the bubble.
func ResolveHost(tb testing.TB, databaseURL string) string {
	tb.Helper()
	u, err := url.Parse(databaseURL)
	if err != nil {
		tb.Fatalf("postgrestest: parse database URL: %v", err)
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = "5432"
	}
	if net.ParseIP(host) != nil {
		return databaseURL
	}
	ctx, cancel := context.WithTimeout(tb.Context(), setupTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		tb.Fatalf("postgrestest: resolve %s: %v", host, err)
	}
	var d net.Dialer
	for _, addr := range addrs {
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr, port))
		if err != nil {
			continue
		}
		_ = conn.Close() // Only the dial mattered.
		u.Host = net.JoinHostPort(addr, port)
		return u.String()
	}
	tb.Fatalf("postgrestest: no address of %s accepts connections on port %s", host, port)
	return ""
}

// UnreachableURL returns the URL of a PostgreSQL server that refuses
// connections: loopback port 1, where nothing listens. The port lies below
// every ephemeral range, so the kernel never gives it to a server that a
// parallel test starts on port 0. A port freed by closing a listener could
// be, and a port bound but not listened on is no better: macOS drops
// connections to it rather than refusing them.
func UnreachableURL(tb testing.TB) string {
	tb.Helper()
	return "postgres://pulsar@127.0.0.1:1/pulsar?sslmode=disable&connect_timeout=1"
}

func serverURL(tb testing.TB) *url.URL {
	tb.Helper()
	raw := os.Getenv(envURL)
	if raw == "" {
		tb.Fatalf("postgrestest: %s is not set; point it at a PostgreSQL server, e.g. postgres://localhost:5432/postgres?sslmode=disable", envURL)
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		tb.Fatalf("postgrestest: %s must be a postgres:// URL", envURL)
	}
	return u
}

// withDatabase returns server's URL with its database replaced by name.
// pgx lets a dbname or database parameter override the path, so both are
// removed.
func withDatabase(server *url.URL, name string) string {
	u := *server
	u.Path = "/" + name
	u.RawPath = ""
	q := u.Query()
	q.Del("dbname")
	q.Del("database")
	u.RawQuery = q.Encode()
	return u.String()
}

// withServer runs f on a new connection to server's maintenance database,
// and closes the connection afterwards.
func withServer(ctx context.Context, server *url.URL, f func(*pgx.Conn) error) error {
	conn, err := pgx.Connect(ctx, server.String())
	if err != nil {
		return fmt.Errorf("connect to %s: %w", envURL, err)
	}
	defer conn.Close(ctx) //nolint:errcheck // Closing after use; a failure loses nothing, and ends the session's locks.
	return f(conn)
}

// exec runs each statement in turn on a new connection to server.
func exec(ctx context.Context, server *url.URL, statements ...string) error {
	return withServer(ctx, server, func(conn *pgx.Conn) error {
		for _, sql := range statements {
			if _, err := conn.Exec(ctx, sql); err != nil {
				return err
			}
		}
		return nil
	})
}

// create clones tmpl into a new database, dropped when the test ends, and
// returns its URL.
func create(tb testing.TB, server *url.URL, tmpl string) string {
	tb.Helper()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(tb.Context()), setupTimeout)
	defer cancel()

	name := "pulsar_test_" + randomHex()
	if err := exec(ctx, server, "CREATE DATABASE "+ident(name)+" TEMPLATE "+ident(tmpl)); err != nil {
		tb.Fatalf("postgrestest: create database: %v", err)
	}
	tb.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(tb.Context()), setupTimeout)
		defer cancel()
		if err := exec(ctx, server, "DROP DATABASE IF EXISTS "+ident(name)+" WITH (FORCE)"); err != nil {
			tb.Errorf("postgrestest: drop %s: %v", name, err)
		}
	})
	return withDatabase(server, name)
}

// templates caches, per test binary, the template for the embedded
// migrations on each server URL.
var templates sync.Map // string → func() (string, error)

// template returns the name of a migrated template database on server,
// building it if no test binary has yet.
func template(server *url.URL) (string, error) {
	build, _ := templates.LoadOrStore(server.String(), sync.OnceValues(func() (string, error) {
		return buildTemplate(server)
	}))
	return build.(func() (string, error))()
}

// buildTemplate builds the template under an advisory lock, so that test
// binaries starting together build it once. It migrates a database under a
// temporary name and renames it only when migration has succeeded, so an
// interrupted build never leaves a template that looks complete.
func buildTemplate(server *url.URL) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), setupTimeout)
	defer cancel()

	sum, err := migrationsSum()
	if err != nil {
		return "", err
	}
	name := "pulsar_template_" + sum
	building := name + "_building"

	err = withServer(ctx, server, func(conn *pgx.Conn) error {
		if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", templateLockID); err != nil {
			return fmt.Errorf("lock: %w", err)
		}
		var exists bool
		if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT FROM pg_database WHERE datname = $1)", name).Scan(&exists); err != nil {
			return fmt.Errorf("look up template: %w", err)
		}
		if exists {
			return nil
		}
		for _, sql := range []string{
			"DROP DATABASE IF EXISTS " + ident(building) + " WITH (FORCE)",
			"CREATE DATABASE " + ident(building) + " TEMPLATE template0",
		} {
			if _, err := conn.Exec(ctx, sql); err != nil {
				return err
			}
		}
		if err := migrate(ctx, withDatabase(server, building)); err != nil {
			return err
		}
		_, err := conn.Exec(ctx, "ALTER DATABASE "+ident(building)+" RENAME TO "+ident(name))
		return err
	})
	if err != nil {
		return "", err
	}
	return name, nil
}

func migrate(ctx context.Context, databaseURL string) error {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return err
	}
	// The pool must be closed, and its connections gone, before the
	// database can be renamed or cloned.
	defer pool.Close()
	_, err = postgres.Migrate(ctx, pool)
	return err
}

// migrationsSum hashes the embedded migrations' names and contents.
func migrationsSum() (string, error) {
	h := sha256.New()
	fsys := postgres.Migrations()
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(h, "%s\x00%d\x00", path, len(b)) // A hash.Hash never returns a write error.
		h.Write(b)
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("hash migrations: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil))[:16], nil
}

func randomHex() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error.
	return hex.EncodeToString(b)
}

func ident(name string) string {
	return pgx.Identifier{name}.Sanitize()
}
