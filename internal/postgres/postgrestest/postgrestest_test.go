package postgrestest_test

import (
	"errors"
	"io/fs"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/palebluedot4/pulsar/internal/postgres"
	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
)

func TestNewDatabase(t *testing.T) {
	t.Parallel()

	migrations, err := fs.Glob(postgres.Migrations(), "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		newDatabase func(testing.TB) string
		want        int // migrations Migrate applies to the new database
	}{
		{name: "NewDatabase", newDatabase: postgrestest.NewDatabase, want: 0},
		{name: "NewEmptyDatabase", newDatabase: postgrestest.NewEmptyDatabase, want: len(migrations)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pool := postgrestest.Open(t, tt.newDatabase(t))
			got, err := postgres.Migrate(t.Context(), pool)
			if err != nil {
				t.Fatalf("Migrate() on a database from %s() error = %v", tt.name, err)
			}
			if got != tt.want {
				t.Errorf("Migrate() on a database from %s() = %d, want %d", tt.name, got, tt.want)
			}
		})
	}
}

func TestNewDatabaseGivesEachTestItsOwn(t *testing.T) {
	t.Parallel()

	a, b := postgrestest.NewDatabase(t), postgrestest.NewDatabase(t)
	if a == b {
		t.Errorf("NewDatabase() = %q twice, want two different databases", a)
	}
}

// ResolveHost names the same database by an IP address, so that pgx, given
// it inside a testing/synctest bubble, never calls net's resolver.
func TestResolveHost(t *testing.T) {
	t.Parallel()

	databaseURL := postgrestest.NewDatabase(t)
	resolved := postgrestest.ResolveHost(t, databaseURL)
	u, err := url.Parse(resolved)
	if err != nil {
		t.Fatal(err)
	}
	if net.ParseIP(u.Hostname()) == nil {
		t.Errorf("ResolveHost(%q) host = %q, want an IP address", databaseURL, u.Hostname())
	}
	var got string
	if err := postgrestest.Open(t, resolved).QueryRow(t.Context(), "SELECT current_database()").Scan(&got); err != nil {
		t.Fatalf("connect to ResolveHost(%q): %v", databaseURL, err)
	}
	original, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.TrimPrefix(original.Path, "/"); got != want {
		t.Errorf("ResolveHost(%q) connects to database %q, want %q", databaseURL, got, want)
	}
}

// The unreachable server refuses connections, and its port stays reserved
// for the whole test, so a server a parallel test starts cannot take it.
func TestUnreachableURL(t *testing.T) {
	t.Parallel()

	u, err := url.Parse(postgrestest.UnreachableURL(t))
	if err != nil {
		t.Fatal(err)
	}
	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", u.Host)
	if err == nil {
		_ = conn.Close() // The dial should not have succeeded; nothing to keep.
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("Dial(%s) error = %v, want %v", u.Host, err, syscall.ECONNREFUSED)
	}

	// The ephemeral range starts at 49152 on macOS and, by default, 32768 on
	// Linux, so a listener on port 0 is never given a port below 1024.
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	if port >= 1024 {
		t.Errorf("UnreachableURL() port = %d, want one below 1024, outside every ephemeral range", port)
	}
}

// childEnv marks a test binary re-executed by runChild.
const childEnv = "POSTGRESTEST_CHILD"

// runChild re-executes the test binary to run only the test named name,
// with PULSAR_TEST_DATABASE_URL set to databaseURL, or unset if it is
// empty, and returns its combined output and exit error.
func runChild(t *testing.T, name, databaseURL string) ([]byte, error) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^"+name+"$", "-test.v") //nolint:gosec // G204: the test re-executes its own binary.
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "PULSAR_TEST_DATABASE_URL=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, childEnv+"=1")
	if databaseURL != "" {
		cmd.Env = append(cmd.Env, "PULSAR_TEST_DATABASE_URL="+databaseURL)
	}
	return cmd.CombinedOutput()
}

// A dbname or database parameter in PULSAR_TEST_DATABASE_URL would, in
// pgx, override the database in the URL's path, so every test would share
// the server's maintenance database. The helper's URLs name the test's
// database however the server's URL is written.
func TestNewDatabaseIgnoresDatabaseParameter(t *testing.T) {
	t.Parallel()

	if os.Getenv(childEnv) == "1" {
		for name, newDatabase := range map[string]func(testing.TB) string{
			"NewDatabase":      postgrestest.NewDatabase,
			"NewEmptyDatabase": postgrestest.NewEmptyDatabase,
		} {
			databaseURL := newDatabase(t)
			u, err := url.Parse(databaseURL)
			if err != nil {
				t.Fatal(err)
			}
			var got string
			if err := postgrestest.Open(t, databaseURL).QueryRow(t.Context(), "SELECT current_database()").Scan(&got); err != nil {
				t.Fatal(err)
			}
			if want := strings.TrimPrefix(u.Path, "/"); got != want {
				t.Errorf("%s() connects to database %q, want %q", name, got, want)
			}
		}
		return
	}

	server, err := url.Parse(os.Getenv("PULSAR_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	for _, param := range []string{"dbname", "database"} {
		u := *server
		q := u.Query()
		q.Set(param, strings.TrimPrefix(u.Path, "/"))
		u.RawQuery = q.Encode()
		if out, err := runChild(t, "TestNewDatabaseIgnoresDatabaseParameter", u.String()); err != nil {
			t.Errorf("databases from a server URL with ?%s= set: test failed: %v\n%s", param, err, out)
		}
	}
}

// A gate that skipped database tests when PostgreSQL was not configured
// would pass without testing anything, so the helper fails the test instead.
func TestNewDatabaseFailsUnset(t *testing.T) {
	t.Parallel()

	if os.Getenv(childEnv) == "1" {
		postgrestest.NewDatabase(t)
		return
	}

	out, err := runChild(t, "TestNewDatabaseFailsUnset", "")
	const call = "NewDatabase() with PULSAR_TEST_DATABASE_URL unset"
	if err == nil {
		t.Fatalf("%s: test exit status = 0, want non-zero:\n%s", call, out)
	}
	if got := strings.Contains(string(out), "--- FAIL") && !strings.Contains(string(out), "--- SKIP"); !got {
		t.Errorf("%s: test failed = %t, want true:\n%s", call, got, out)
	}
	if got := strings.Contains(string(out), "PULSAR_TEST_DATABASE_URL is not set"); !got {
		t.Errorf("%s: failure names the variable = %t, want true:\n%s", call, got, out)
	}
}
