package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3/lock"

	"github.com/palebluedot4/pulsar/internal/postgres"
	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
)

// loopbackIssuer is an issuer pulsar accepts without TLS, for tests about
// something else.
const loopbackIssuer = "http://127.0.0.1"

func TestRun(t *testing.T) {
	t.Parallel()

	p := start(t, map[string]string{
		"PULSAR_ISSUER":       loopbackIssuer,
		"PULSAR_DATABASE_URL": postgrestest.NewDatabase(t),
	})
	addr := p.waitListening()
	p.waitMigrated()

	for _, path := range []string{"/livez", "/readyz"} {
		if got := status(t, "http://"+addr+path); got != http.StatusOK {
			t.Errorf("GET %s status = %d, want %d", path, got, http.StatusOK)
		}
	}

	if err := p.stop(); err != nil {
		t.Errorf("run() = %v, want nil after cancellation", err)
	}
}

// REQ-DISC-1, REQ-DISC-17: an issuer that is https, or http on a loopback
// host, is accepted and published exactly as configured.
func TestRunPublishesIssuer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		issuer string
		path   string
	}{
		{issuer: "https://op.example", path: "/.well-known/openid-configuration"},
		{issuer: "https://op.example:8443/tenant", path: "/tenant/.well-known/openid-configuration"},
		{issuer: "http://127.0.0.1:8080", path: "/.well-known/openid-configuration"},
		{issuer: "http://[::1]", path: "/.well-known/openid-configuration"},
		{issuer: "http://localhost", path: "/.well-known/openid-configuration"},
	}
	for _, tt := range tests {
		t.Run(tt.issuer, func(t *testing.T) {
			t.Parallel()
			p := start(t, map[string]string{
				"PULSAR_ISSUER":       tt.issuer,
				"PULSAR_DATABASE_URL": postgrestest.NewDatabase(t),
			})
			addr := p.waitListening()
			if got := discoveredIssuer(t, http.DefaultClient, "http://"+addr+tt.path); got != tt.issuer {
				t.Errorf("GET %s issuer = %q, want %q", tt.path, got, tt.issuer)
			}
			if err := p.stop(); err != nil {
				t.Errorf("run() = %v, want nil after cancellation", err)
			}
		})
	}
}

func TestRunServesTLS(t *testing.T) {
	t.Parallel()

	certFile, keyFile, roots := writeCertificate(t)
	p := start(t, map[string]string{
		"PULSAR_ISSUER":       "https://127.0.0.1",
		"PULSAR_DATABASE_URL": postgrestest.NewDatabase(t),
		"PULSAR_TLS_CERT":     certFile,
		"PULSAR_TLS_KEY":      keyFile,
	})
	addr := p.waitListening()
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}}
	if got, want := discoveredIssuer(t, client, "https://"+addr+"/.well-known/openid-configuration"), "https://127.0.0.1"; got != want {
		t.Errorf("GET /.well-known/openid-configuration over TLS issuer = %q, want %q", got, want)
	}
	if err := p.stop(); err != nil {
		t.Errorf("run() = %v, want nil after cancellation", err)
	}
}

// REQ-DISC-1: the issuer must be an https URL with no query or fragment; the
// loopback exception is the departure recorded beside it. REQ-DISC-13: an
// issuer never has a terminating slash to remove.
func TestRunRefusesInvalidConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		env     map[string]string
		setting string // the setting the error must name
	}{
		{name: "missing issuer", env: map[string]string{}, setting: "PULSAR_ISSUER"},
		{name: "relative issuer", env: map[string]string{"PULSAR_ISSUER": "/op"}, setting: "PULSAR_ISSUER"},
		{name: "issuer without host", env: map[string]string{"PULSAR_ISSUER": "https:///op"}, setting: "PULSAR_ISSUER"},
		{name: "http issuer", env: map[string]string{"PULSAR_ISSUER": "http://op.example"}, setting: "PULSAR_ISSUER"},
		{name: "http issuer under localhost", env: map[string]string{"PULSAR_ISSUER": "http://localhost.op.example"}, setting: "PULSAR_ISSUER"},
		{name: "other scheme", env: map[string]string{"PULSAR_ISSUER": "ftp://op.example"}, setting: "PULSAR_ISSUER"},
		{name: "issuer with fragment", env: map[string]string{"PULSAR_ISSUER": "https://op.example#top"}, setting: "PULSAR_ISSUER"},
		{name: "issuer with empty fragment", env: map[string]string{"PULSAR_ISSUER": "https://op.example#"}, setting: "PULSAR_ISSUER"},
		{name: "issuer with query", env: map[string]string{"PULSAR_ISSUER": "https://op.example?tenant=a"}, setting: "PULSAR_ISSUER"},
		{name: "issuer with empty query", env: map[string]string{"PULSAR_ISSUER": "https://op.example?"}, setting: "PULSAR_ISSUER"},
		{name: "issuer with userinfo", env: map[string]string{"PULSAR_ISSUER": "https://user@op.example"}, setting: "PULSAR_ISSUER"},
		{name: "issuer with empty port", env: map[string]string{"PULSAR_ISSUER": "https://op.example:"}, setting: "PULSAR_ISSUER"},
		{name: "issuer with default https port", env: map[string]string{"PULSAR_ISSUER": "https://op.example:443"}, setting: "PULSAR_ISSUER"},
		{name: "issuer with default http port", env: map[string]string{"PULSAR_ISSUER": "http://localhost:80"}, setting: "PULSAR_ISSUER"},
		{name: "issuer with uppercase host", env: map[string]string{"PULSAR_ISSUER": "https://OP.example"}, setting: "PULSAR_ISSUER"},
		{name: "issuer with dot segment", env: map[string]string{"PULSAR_ISSUER": "https://op.example/."}, setting: "PULSAR_ISSUER"},
		{name: "issuer with encoded dot segment", env: map[string]string{"PULSAR_ISSUER": "https://op.example/%2e"}, setting: "PULSAR_ISSUER"},
		{name: "issuer with dot-dot segment", env: map[string]string{"PULSAR_ISSUER": "https://op.example/a/../b"}, setting: "PULSAR_ISSUER"},
		{name: "issuer with empty segment", env: map[string]string{"PULSAR_ISSUER": "https://op.example//tenant"}, setting: "PULSAR_ISSUER"},
		{name: "issuer not in canonical form", env: map[string]string{"PULSAR_ISSUER": "HTTPS://op.example"}, setting: "PULSAR_ISSUER"},
		{name: "issuer ending with slash", env: map[string]string{"PULSAR_ISSUER": "https://op.example/"}, setting: "PULSAR_ISSUER"},
		{name: "issuer path ending with slash", env: map[string]string{"PULSAR_ISSUER": "https://op.example/tenant/"}, setting: "PULSAR_ISSUER"},
		{
			name: "TLS with http issuer",
			env: map[string]string{
				"PULSAR_ISSUER":   "http://127.0.0.1",
				"PULSAR_TLS_CERT": "cert.pem",
				"PULSAR_TLS_KEY":  "key.pem",
			},
			setting: "PULSAR_ISSUER",
		},
		{
			name:    "certificate without key",
			env:     map[string]string{"PULSAR_ISSUER": "https://op.example", "PULSAR_TLS_CERT": "cert.pem"},
			setting: "PULSAR_TLS_KEY",
		},
		{
			name:    "key without certificate",
			env:     map[string]string{"PULSAR_ISSUER": "https://op.example", "PULSAR_TLS_KEY": "key.pem"},
			setting: "PULSAR_TLS_CERT",
		},
		{
			name: "unreadable certificate and key",
			env: map[string]string{
				"PULSAR_ISSUER":   "https://op.example",
				"PULSAR_TLS_CERT": "testdata/missing-cert.pem",
				"PULSAR_TLS_KEY":  "testdata/missing-key.pem",
			},
			setting: "PULSAR_TLS_CERT",
		},
	}
	// A well-formed database URL, so that no case fails for want of one.
	// The context below is canceled, so it is never connected to.
	databaseURL := postgrestest.UnreachableURL(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// The context is canceled from the start, so a configuration
			// wrongly accepted makes run return at once instead of serving.
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			env := maps.Clone(tt.env)
			env["PULSAR_ADDR"] = "127.0.0.1:0"
			env["PULSAR_DATABASE_URL"] = databaseURL
			getenv := func(key string) string { return env[key] }
			err := run(ctx, nil, getenv, strings.NewReader(""), io.Discard, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tt.setting) {
				t.Errorf("run() = %v, want an error naming %s", err, tt.setting)
			}
		})
	}
}

func TestRunDoesNotEchoIssuerPassword(t *testing.T) {
	t.Parallel()

	const password = "hunter2"
	issuers := []string{
		"https://user:" + password + "@op.example",
		"https://user:" + password + "@op.example:abc", // fails to parse
		"https://user:" + password + "@/tenant",        // has no host
	}
	for _, issuer := range issuers {
		t.Run(issuer, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			cancel() // As in TestRunRefusesInvalidConfig.
			env := map[string]string{"PULSAR_ADDR": "127.0.0.1:0", "PULSAR_ISSUER": issuer}
			getenv := func(key string) string { return env[key] }
			err := run(ctx, nil, getenv, strings.NewReader(""), io.Discard, io.Discard)
			if err == nil || !strings.Contains(err.Error(), "PULSAR_ISSUER") || strings.Contains(err.Error(), password) {
				t.Errorf("run() = %v, want an error naming PULSAR_ISSUER without the password", err)
			}
		})
	}
}

// pulsar refuses to start when PULSAR_DATABASE_URL is unusable, with an
// error that names the setting and never repeats the password in it.
func TestRunRefusesDatabaseURL(t *testing.T) {
	t.Parallel()

	unreachable, err := url.Parse(postgrestest.UnreachableURL(t))
	if err != nil {
		t.Fatal(err)
	}
	unreachable.User = url.UserPassword("pulsar", "hunter2")

	tests := []struct {
		name        string
		databaseURL string
	}{
		{name: "unset", databaseURL: ""},
		{name: "malformed", databaseURL: "not a connection string"},
		{name: "malformed, with a password", databaseURL: "postgres://pulsar:hunter2@localhost:notaport/pulsar"},
		{name: "unreachable, with a password", databaseURL: unreachable.String()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := map[string]string{
				"PULSAR_ADDR":         "127.0.0.1:0",
				"PULSAR_ISSUER":       loopbackIssuer,
				"PULSAR_DATABASE_URL": tt.databaseURL,
			}
			getenv := func(key string) string { return env[key] }
			err := run(t.Context(), nil, getenv, strings.NewReader(""), io.Discard, io.Discard)
			if err == nil {
				t.Fatal("run() = nil, want an error naming PULSAR_DATABASE_URL")
			}
			if !strings.Contains(err.Error(), "PULSAR_DATABASE_URL") {
				t.Errorf("run() = %q, want an error naming PULSAR_DATABASE_URL", err)
			}
			if strings.Contains(err.Error(), "hunter2") {
				t.Errorf("run() = %q, want an error without the password", err)
			}
		})
	}
}

// Restarting pulsar against a database it has already migrated applies
// nothing, and fails nothing.
func TestRunMigratesOnce(t *testing.T) {
	t.Parallel()

	env := map[string]string{
		"PULSAR_ISSUER":       loopbackIssuer,
		"PULSAR_DATABASE_URL": postgrestest.NewEmptyDatabase(t),
	}

	first := start(t, env)
	applied := first.waitMigrated()
	if err := first.stop(); err != nil {
		t.Fatalf("first run() = %v, want nil", err)
	}
	if applied == 0 {
		t.Errorf("first run() applied = %d migrations, want more than 0", applied)
	}

	second := start(t, env)
	applied = second.waitMigrated()
	if err := second.stop(); err != nil {
		t.Fatalf("second run() = %v, want nil", err)
	}
	if applied != 0 {
		t.Errorf("second run() applied = %d migrations, want 0", applied)
	}
}

// Replicas starting together against a new database migrate it once: one
// applies the migrations and the other, held by the lock, finds none left.
func TestRunConcurrentStartsMigrateOnce(t *testing.T) {
	t.Parallel()

	env := map[string]string{
		"PULSAR_ISSUER":       loopbackIssuer,
		"PULSAR_DATABASE_URL": postgrestest.NewEmptyDatabase(t),
	}
	replicas := []*pulsar{start(t, env), start(t, env)}

	var applied []int
	for _, p := range replicas {
		applied = append(applied, p.waitMigrated())
	}
	for _, p := range replicas {
		if err := p.stop(); err != nil {
			t.Errorf("run() = %v, want nil", err)
		}
	}
	migrated := 0
	for _, n := range applied {
		if n > 0 {
			migrated++
		}
	}
	if migrated != 1 {
		t.Errorf("concurrent run() applied = %v migrations, want exactly one run to apply more than 0", applied)
	}
}

// While another replica migrates, pulsar waits for it rather than migrating
// too. The other replica is stood in for by a session holding goose's
// advisory lock; the lock's ID is part of the contract, since replicas of
// two releases must exclude each other during a rolling deploy.
//
// The wait is on the real clock, not in a testing/synctest bubble. The
// bubble cannot hold this test: pulsar talks to a real PostgreSQL, and a
// goroutine waiting on the network is not durably blocked, so the bubble's
// clock gains nothing; and process-wide state that the bubble initializes
// first belongs to it. Tried on 2026-11-05, the test binary crashed with
// "select on synctest channel from outside bubble" when a parallel test
// resolved localhost after the bubble had started net's resolver.
//
// It serves meanwhile: /livez answers at once, so a liveness probe does not
// kill a replica that is rightly waiting, and /readyz answers 503 until the
// migrations are applied.
func TestRunWaitsForMigrationLock(t *testing.T) {
	t.Parallel()

	databaseURL := postgrestest.NewEmptyDatabase(t)
	unlock := holdMigrationLock(t, databaseURL)

	p := start(t, map[string]string{
		"PULSAR_ISSUER":       loopbackIssuer,
		"PULSAR_DATABASE_URL": databaseURL,
	})
	addr := p.waitListening()
	// Long enough for pulsar to have tried the lock, and retried it once.
	wait := postgres.LockRetryInterval * 3 / 2
	select {
	case b, ok := <-p.lines:
		if ok {
			t.Fatalf("run() logged %s while another session held the migration lock, want no log line before it is released", b)
		}
		t.Fatalf("run() = %v while another session held the migration lock, want it to wait", <-p.done)
	case <-time.After(wait):
	}
	if got := status(t, "http://"+addr+"/livez"); got != http.StatusOK {
		t.Errorf("GET /livez while waiting for the migration lock status = %d, want %d", got, http.StatusOK)
	}
	if got := status(t, "http://"+addr+"/readyz"); got != http.StatusServiceUnavailable {
		t.Errorf("GET /readyz while waiting for the migration lock status = %d, want %d", got, http.StatusServiceUnavailable)
	}

	unlock()
	if applied := p.waitMigrated(); applied == 0 {
		t.Errorf("run() after the lock was released applied = %d migrations, want more than 0", applied)
	}
	if got := status(t, "http://"+addr+"/readyz"); got != http.StatusOK {
		t.Errorf("GET /readyz after migrating status = %d, want %d", got, http.StatusOK)
	}
	if err := p.stop(); err != nil {
		t.Errorf("run() = %v, want nil", err)
	}
}

// A signal while pulsar waits to migrate, as when a rolling deploy replaces
// a replica that is still starting, is a graceful exit like one while it
// serves, not a database fault.
func TestRunStopsWhileWaitingForMigrationLock(t *testing.T) {
	t.Parallel()

	databaseURL := postgrestest.NewEmptyDatabase(t)
	holdMigrationLock(t, databaseURL)

	p := start(t, map[string]string{
		"PULSAR_ISSUER":       loopbackIssuer,
		"PULSAR_DATABASE_URL": databaseURL,
	})
	p.waitListening()
	if err := p.stop(); err != nil {
		t.Errorf("run() stopped while waiting for the migration lock = %v, want nil", err)
	}
}

// holdMigrationLock takes goose's migration lock on databaseURL from a
// session of the test's own, as another replica migrating would hold it,
// and returns a function that releases it. The session ends with the test.
func holdMigrationLock(t *testing.T, databaseURL string) (unlock func()) {
	t.Helper()
	conn, err := pgx.Connect(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.WithoutCancel(t.Context())) }) // Closing after use; a failure loses nothing.
	if _, err := conn.Exec(t.Context(), "SELECT pg_advisory_lock($1)", lock.DefaultLockID); err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		if _, err := conn.Exec(t.Context(), "SELECT pg_advisory_unlock($1)", lock.DefaultLockID); err != nil {
			t.Fatal(err)
		}
	}
}

// pulsar is a running instance of run, observed as an operator would: through
// its logs, its HTTP address and its exit error.
type pulsar struct {
	t      *testing.T
	cancel context.CancelFunc
	done   chan error  // receives run's result
	lines  chan []byte // log lines, closed when run's output ends
}

// start runs pulsar on a free loopback port with env, and nothing else, as
// its environment.
func start(t *testing.T, env map[string]string) *pulsar {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	env = maps.Clone(env)
	env["PULSAR_ADDR"] = "127.0.0.1:0"
	getenv := func(key string) string { return env[key] }
	logs, stdout := io.Pipe()
	p := &pulsar{t: t, cancel: cancel, done: make(chan error, 1), lines: make(chan []byte, 64)}

	go func() {
		p.done <- run(ctx, nil, getenv, strings.NewReader(""), stdout, io.Discard)
		_ = stdout.Close() // An io.PipeWriter's Close always returns nil.
	}()
	go func() {
		defer close(p.lines)
		sc := bufio.NewScanner(logs)
		for sc.Scan() {
			p.lines <- bytes.Clone(sc.Bytes())
		}
	}()
	t.Cleanup(cancel)
	return p
}

// logLine is a JSON log line, with the attributes the tests read.
type logLine struct {
	Msg     string `json:"msg"`
	Addr    string `json:"addr"`
	Applied int    `json:"applied"`
}

// logWait bounds how long a test waits for a log line, so that a pulsar
// that never logs it fails the test instead of hanging it.
const logWait = 30 * time.Second

// waitFor reads log lines until one has msg, and returns it.
func (p *pulsar) waitFor(msg string) logLine {
	p.t.Helper()
	timeout := time.After(logWait)
	for {
		select {
		case b, ok := <-p.lines:
			if !ok {
				p.t.Fatalf("run() = %v before logging %q, want it to log %q", <-p.done, msg, msg)
			}
			var line logLine
			if err := json.Unmarshal(b, &line); err != nil {
				p.t.Fatalf("log line %q is not JSON: %v", b, err)
			}
			if line.Msg == msg {
				return line
			}
		case <-timeout:
			p.t.Fatalf("run() logged no %q within %v", msg, logWait)
		}
	}
}

// waitListening waits until the instance reports the address it listens
// on, and returns it.
func (p *pulsar) waitListening() string {
	p.t.Helper()
	return p.waitFor("listening").Addr
}

// waitMigrated waits until the instance reports its migrations applied, and
// returns how many it applied.
func (p *pulsar) waitMigrated() int {
	p.t.Helper()
	return p.waitFor("migrated").Applied
}

// stop cancels the instance and returns run's result.
func (p *pulsar) stop() error {
	p.cancel()
	go func() {
		for range p.lines {
		}
	}()
	return <-p.done
}

// get sends a GET request to url and fails the test if none comes back.
func get(t *testing.T, client *http.Client, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

// status sends a GET request to url and returns the response's status code.
func status(t *testing.T, url string) int {
	t.Helper()
	resp := get(t, http.DefaultClient, url)
	if err := resp.Body.Close(); err != nil {
		t.Errorf("close body: %v", err)
	}
	return resp.StatusCode
}

// discoveredIssuer fetches the discovery document at url and returns its
// issuer.
func discoveredIssuer(t *testing.T, client *http.Client, url string) string {
	t.Helper()
	resp := get(t, client, url)
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("close body: %v", err)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want %d", url, resp.StatusCode, http.StatusOK)
	}
	var doc struct {
		Issuer string `json:"issuer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("GET %s: decode body: %v", url, err)
	}
	return doc.Issuer
}

// writeCertificate writes a self-signed certificate for 127.0.0.1, and its
// key, to PEM files, and returns their names and a pool that trusts it.
func writeCertificate(t *testing.T) (certFile, keyFile string, roots *x509.CertPool) {
	t.Helper()
	// Not cryptotest.SetGlobalRandom: the key need not be reproducible, and
	// resetting the process-wide source at cleanup races with TLS
	// connections that close in the background. Closing the client's
	// connections first is not enough: the server's connection goroutines
	// send their own close_notify after Shutdown returns.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The client checks the validity period against the wall clock, so
	// this cannot run in a synctest bubble.
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		t.Fatal(err)
	}
	roots = x509.NewCertPool()
	roots.AddCert(cert)
	return certFile, keyFile, roots
}
