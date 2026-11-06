package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/argon2"

	"github.com/palebluedot4/pulsar/internal/config"
	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
	"github.com/palebluedot4/pulsar/internal/registry"
	"github.com/palebluedot4/pulsar/internal/signing"
)

// loginIssuer has a path, so that the tests also show that the login page
// is served under it.
const (
	loginIssuer = "https://op.example/tenant"
	loginPath   = "/tenant/login"
)

// sessionCookie is the Login Session cookie's name.
const sessionCookie = "__Host-pulsar-session"

// The End-Users the tests sign in as, with their passwords.
const (
	alicePassword = "correct horse battery staple"
	bobPassword   = "Tr0ub4dor&3" //nolint:gosec // G101: a test value, guarding nothing.
)

// failedLogin is what a failed login says, and all it says.
const failedLogin = "The username or password is incorrect."

// hashPassword returns an Argon2id PHC string for password, with
// parameters far below any production setting so that tests run fast.
func hashPassword(t *testing.T, password string) string {
	t.Helper()
	salt := make([]byte, 16)
	_, _ = rand.Read(salt) // crypto/rand.Read never returns an error.
	key := argon2.IDKey([]byte(password), salt, 1, 64, 1, 32)
	enc := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf("$argon2id$v=19$m=64,t=1,p=1$%s$%s", enc(salt), enc(key))
}

// testRegistry returns a registry of two End-Users, alice and bob.
func testRegistry(t *testing.T) *registry.Registry {
	t.Helper()
	reg, err := registry.Parse([]byte(`{"end_users": [
		{"sub": "7c9e6679-7425-40de-944b-e07fc1f90ae7", "username": "alice", "password_hash": "` + hashPassword(t, alicePassword) + `"},
		{"sub": "0b5c3c62-1f3e-4f2b-9f43-8c1d2e3f4a5b", "username": "bob", "password_hash": "` + hashPassword(t, bobPassword) + `"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// newLoginHandler returns the handler of an OP at loginIssuer, with the
// End-Users of testRegistry, backed by pool.
func newLoginHandler(t *testing.T, pool *pgxpool.Pool) http.Handler {
	t.Helper()
	return New(slog.New(slog.NewTextHandler(t.Output(), nil)), mustParse(t, loginIssuer), pool, signing.New(pool, config.Secret{}), testRegistry(t), ready())
}

// browser stands in for an End-User's browser: it sends requests to a
// handler and keeps the Login Session cookie the handler last set. It keeps
// the cookie past any expiry the cookie states, as an attacker who copied
// it would, so that a test sees what the server itself enforces.
type browser struct {
	t       *testing.T
	handler http.Handler
	session *http.Cookie
}

// response is what the handler answered.
type response struct {
	status int
	header http.Header
	body   string
}

// do sends req, with the Login Session cookie if there is one, and records
// any new one from the response.
func (b *browser) do(req *http.Request) response {
	b.t.Helper()
	if b.session != nil {
		req.Header.Set("Cookie", b.session.Name+"="+b.session.Value)
	}
	rec := httptest.NewRecorder()
	b.handler.ServeHTTP(rec, req)
	resp := rec.Result()
	defer resp.Body.Close() //nolint:errcheck // A recorder's body cannot fail to close.
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			b.session = c
		}
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		b.t.Fatal(err)
	}
	return response{status: resp.StatusCode, header: resp.Header, body: string(body)}
}

// get sends GET for the login page.
func (b *browser) get() response {
	b.t.Helper()
	return b.do(httptest.NewRequestWithContext(b.t.Context(), http.MethodGet, "https://op.example"+loginPath, http.NoBody))
}

// login submits the login form with username and password, and with
// header, which may be nil.
func (b *browser) login(username, password string, header http.Header) response {
	b.t.Helper()
	form := url.Values{"username": {username}, "password": {password}}
	req := httptest.NewRequestWithContext(b.t.Context(), http.MethodPost, "https://op.example"+loginPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	maps.Copy(req.Header, header)
	return b.do(req)
}

// signedInAs returns the username the login page says the browser is
// signed in as, or "" if it shows the login form.
func (b *browser) signedInAs() string {
	b.t.Helper()
	resp := b.get()
	if resp.status != http.StatusOK {
		b.t.Fatalf("GET %s status = %d, want %d", loginPath, resp.status, http.StatusOK)
	}
	_, after, ok := strings.Cut(resp.body, "Signed in as ")
	if !ok {
		return ""
	}
	name, _, _ := strings.Cut(after, ".")
	return name
}

// REQ-BCP-2: the login page may not be framed, so it cannot be overlaid
// to capture a password.
func TestLoginPage(t *testing.T) {
	t.Parallel()

	b := &browser{t: t, handler: newLoginHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))}
	resp := b.get()
	if resp.status != http.StatusOK {
		t.Fatalf("GET %s status = %d, want %d", loginPath, resp.status, http.StatusOK)
	}
	wantHeader := map[string]string{
		"Content-Type":            "text/html; charset=utf-8",
		"Cache-Control":           "no-store",
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
	}
	gotHeader := make(map[string]string, len(wantHeader))
	for k := range wantHeader {
		gotHeader[k] = resp.header.Get(k)
	}
	if diff := cmp.Diff(wantHeader, gotHeader); diff != "" {
		t.Errorf("GET %s headers mismatch (-want +got):\n%s", loginPath, diff)
	}
	for _, want := range []string{`<form method="post">`, `name="username"`, `name="password" type="password"`} {
		if !strings.Contains(resp.body, want) {
			t.Errorf("GET %s body = %q, want it to contain %q", loginPath, resp.body, want)
		}
	}
	// Visiting the page starts no Login Session.
	if b.session != nil {
		t.Errorf("GET %s set cookie %q, want none", loginPath, b.session.Name)
	}
}

// Until the database is migrated, the login page answers 503, as /readyz
// does, rather than fail on a table that does not exist yet.
func TestLoginBeforeReady(t *testing.T) {
	t.Parallel()

	pool := postgrestest.Open(t, postgrestest.NewEmptyDatabase(t))
	logger := slog.New(slog.NewTextHandler(t.Output(), nil))
	handler := New(logger, mustParse(t, loginIssuer), pool, signing.New(pool, config.Secret{}), testRegistry(t), make(chan struct{}))
	b := &browser{t: t, handler: handler}
	for name, resp := range map[string]response{
		"GET":  b.get(),
		"POST": b.login("alice", alicePassword, nil),
	} {
		if resp.status != http.StatusServiceUnavailable {
			t.Errorf("%s %s before ready status = %d, want %d", name, loginPath, resp.status, http.StatusServiceUnavailable)
		}
	}
}

// A correct username and password start a Login Session, whose cookie is
// __Host- prefixed, Secure, HttpOnly and SameSite=Lax: Lax rather than
// Strict, so that the top-level navigation from a Client that carries an
// authorization request sends it.
func TestLogin(t *testing.T) {
	t.Parallel()

	b := &browser{t: t, handler: newLoginHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))}
	resp := b.login("alice", alicePassword, nil)
	if resp.status != http.StatusSeeOther {
		t.Fatalf("POST %s with a correct password status = %d, want %d", loginPath, resp.status, http.StatusSeeOther)
	}
	if got := resp.header.Get("Location"); got != loginPath {
		t.Errorf("POST %s with a correct password Location = %q, want %q", loginPath, got, loginPath)
	}
	if b.session == nil {
		t.Fatalf("POST %s with a correct password set no %s cookie", loginPath, sessionCookie)
	}
	type attributes struct {
		Path     string
		Domain   string
		Secure   bool
		HTTPOnly bool
		SameSite http.SameSite
	}
	want := attributes{Path: "/", Secure: true, HTTPOnly: true, SameSite: http.SameSiteLaxMode}
	c := b.session
	got := attributes{Path: c.Path, Domain: c.Domain, Secure: c.Secure, HTTPOnly: c.HttpOnly, SameSite: c.SameSite}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("POST %s %s cookie attributes mismatch (-want +got):\n%s", loginPath, sessionCookie, diff)
	}
	if got := b.signedInAs(); got != "alice" {
		t.Errorf("GET %s after login signed in as %q, want %q", loginPath, got, "alice")
	}
}

// A failed login says only that the username or password is wrong, in the
// same response whether or not the username exists, and starts no Login
// Session.
func TestLoginFailure(t *testing.T) {
	t.Parallel()

	handler := newLoginHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	tests := []struct {
		name     string
		username string
		password string
	}{
		{name: "wrong password", username: "alice", password: bobPassword},
		{name: "unknown username", username: "carol", password: alicePassword},
		{name: "username in another case", username: "Alice", password: alicePassword},
		{name: "no password", username: "alice", password: ""},
		{name: "no username", username: "", password: alicePassword},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := &browser{t: t, handler: handler}
			resp := b.login(tt.username, tt.password, nil)
			if resp.status != http.StatusOK {
				t.Errorf("POST %s status = %d, want %d", loginPath, resp.status, http.StatusOK)
			}
			// The form is shown again with the username as typed, so the
			// body differs between cases only by it.
			body := strings.ReplaceAll(resp.body, `value="`+tt.username+`"`, `value=""`)
			if !strings.Contains(body, failedLogin) {
				t.Errorf("POST %s body = %q, want it to contain %q", loginPath, body, failedLogin)
			}
			if b.session != nil {
				t.Errorf("POST %s set cookie %q, want none", loginPath, b.session.Name)
			}

			reference := &browser{t: t, handler: handler}
			want := strings.ReplaceAll(reference.login("alice", "wrong", nil).body, `value="alice"`, `value=""`)
			if diff := cmp.Diff(want, body); diff != "" {
				t.Errorf("POST %s body mismatch with a wrong password's (-want +got):\n%s", loginPath, diff)
			}
		})
	}
}

// Credentials in the query string are not read, so that a password never
// travels in a URL, where logs and the Referer header keep it.
func TestLoginIgnoresQuery(t *testing.T) {
	t.Parallel()

	b := &browser{t: t, handler: newLoginHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))}
	query := url.Values{"username": {"alice"}, "password": {alicePassword}}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://op.example"+loginPath+"?"+query.Encode(), http.NoBody)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	b.do(req)
	if b.session != nil {
		t.Errorf("POST %s with credentials in the query set cookie %q, want none", loginPath, b.session.Name)
	}
}

// The Login Session token changes at login, so a token planted in a browser
// before it signs in is worthless afterward.
func TestLoginRenewsSessionToken(t *testing.T) {
	t.Parallel()

	b := &browser{t: t, handler: newLoginHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))}
	b.login("alice", alicePassword, nil)
	if b.session == nil {
		t.Fatalf("POST %s with a correct password set no %s cookie", loginPath, sessionCookie)
	}
	before := *b.session

	b.login("bob", bobPassword, nil)
	if b.session.Value == before.Value {
		t.Fatalf("POST %s again kept the Login Session token, want a new one", loginPath)
	}
	if got := b.signedInAs(); got != "bob" {
		t.Errorf("GET %s with the new token signed in as %q, want %q", loginPath, got, "bob")
	}
	old := &browser{t: t, handler: b.handler, session: &before}
	if got := old.signedInAs(); got != "" {
		t.Errorf("GET %s with the token from before the login signed in as %q, want not signed in", loginPath, got)
	}
}

// A Login Session ends after 30 minutes without a request, or 10 hours
// after login however active it is. The server ends it, whatever the
// cookie's own expiry.
//
// The pool is opened inside the bubble, on an address rather than a host
// name, as in signing's TestJWKSReloadsKeyFromAnotherReplica.
func TestLoginSessionLimits(t *testing.T) {
	t.Parallel()

	const (
		idle     = 30 * time.Minute
		absolute = 10 * time.Hour
	)
	tests := []struct {
		name  string
		steps []time.Duration // waits between requests, each followed by a check that the Login Session lives
		end   time.Duration   // the wait after which it has ended
	}{
		{name: "idle", steps: []time.Duration{idle - time.Second, idle - time.Second}, end: idle},
		{name: "absolute", steps: repeat(int(absolute/(idle-time.Minute)), idle-time.Minute), end: absolute % (idle - time.Minute)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
			synctest.Test(t, func(t *testing.T) {
				pool, err := pgxpool.New(t.Context(), databaseURL)
				if err != nil {
					t.Fatal(err)
				}
				defer pool.Close()
				b := &browser{t: t, handler: newLoginHandler(t, pool)}
				b.login("alice", alicePassword, nil)

				var elapsed time.Duration
				for _, d := range tt.steps {
					time.Sleep(d)
					elapsed += d
					if got := b.signedInAs(); got != "alice" {
						t.Fatalf("GET %s %v after login signed in as %q, want %q", loginPath, elapsed, got, "alice")
					}
				}
				time.Sleep(tt.end)
				elapsed += tt.end
				if got := b.signedInAs(); got != "" {
					t.Errorf("GET %s %v after login signed in as %q, want not signed in", loginPath, elapsed, got)
				}
			})
		})
	}
}

// repeat returns n copies of d.
func repeat(n int, d time.Duration) []time.Duration {
	ds := make([]time.Duration, n)
	for i := range ds {
		ds[i] = d
	}
	return ds
}

// The login form refuses a cross-origin submission, as a browser marks it,
// so that another site cannot sign a browser in with credentials of its
// choosing; a same-origin one, or one from outside a browser, is accepted.
func TestLoginRefusesCrossOrigin(t *testing.T) {
	t.Parallel()

	handler := newLoginHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	tests := []struct {
		name   string
		header http.Header
		want   int
	}{
		{name: "cross-site", header: http.Header{"Sec-Fetch-Site": {"cross-site"}}, want: http.StatusForbidden},
		{name: "same-site", header: http.Header{"Sec-Fetch-Site": {"same-site"}}, want: http.StatusForbidden},
		{name: "other origin, without Sec-Fetch-Site", header: http.Header{"Origin": {"https://attacker.example"}}, want: http.StatusForbidden},
		{name: "same-origin", header: http.Header{"Sec-Fetch-Site": {"same-origin"}}, want: http.StatusSeeOther},
		{name: "outside a browser", header: nil, want: http.StatusSeeOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := &browser{t: t, handler: handler}
			resp := b.login("alice", alicePassword, tt.header)
			if resp.status != tt.want {
				t.Errorf("POST %s %s status = %d, want %d", loginPath, tt.name, resp.status, tt.want)
			}
			if signedIn := b.session != nil; signedIn != (tt.want == http.StatusSeeOther) {
				t.Errorf("POST %s %s set a Login Session cookie: %v, want %v", loginPath, tt.name, signedIn, !signedIn)
			}
		})
	}
}
