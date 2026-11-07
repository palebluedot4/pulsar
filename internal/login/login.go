// Package login serves the login and consent pages, and keeps the Login
// Session that a successful login starts and the Consents End-Users give,
// for the authorization endpoint to read.
//
// A Login Session is kept by scs, server-side in PostgreSQL. Its cookie
// has the __Host- prefix and is Secure and HttpOnly, and SameSite=Lax
// rather than Strict, because Strict would drop it on the top-level
// cross-site navigation that carries an authorization request. A Login
// Session ends 30 minutes after its last request or 10 hours after login,
// whichever comes first, and its token is replaced at each login, so that
// a token planted in a browser beforehand is worthless afterward.
//
// The login and consent forms refuse cross-origin submissions, through
// [http.CrossOriginProtection], and neither page may be framed.
package login

import (
	"bytes"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palebluedot4/pulsar/internal/login/internal/queries"
	"github.com/palebluedot4/pulsar/internal/registry"
)

// Path is the login page's path, relative to the issuer.
const Path = "/login"

// Login Session limits.
const (
	idleTimeout = 30 * time.Minute
	lifetime    = 10 * time.Hour
)

// cookieName is the Login Session cookie's name. The __Host- prefix makes
// a browser accept the cookie only if it is Secure, has Path=/ and has no
// Domain, so that no other host, such as a sibling subdomain, can set it.
const cookieName = "__Host-pulsar-session"

// Keys of the values a Login Session holds.
const (
	subjectKey  = "sub"       // the End-User's Subject
	authTimeKey = "auth_time" // when the End-User authenticated, in seconds since the epoch
)

// maxFormSize bounds the login form's body.
const maxFormSize = 64 << 10

// failedLogin is all a failed login says, whatever the reason, so that the
// page does not tell which usernames exist.
const failedLogin = "The username or password is incorrect."

// Headers of every page this package serves. The page is personal and
// must not be cached. It runs no script and loads nothing, and no other
// page may frame it, which is how RFC 9700 §4.16 has an authorization
// server prevent clickjacking; X-Frame-Options does the same for browsers
// without CSP frame-ancestors.
var pageHeaders = map[string]string{
	"Content-Type":            "text/html; charset=utf-8",
	"Cache-Control":           "no-store",
	"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
	"X-Frame-Options":         "DENY",
}

// SetPageHeaders sets on h the headers of every page pulsar serves: the
// login and consent pages, and the authorization endpoint's error page.
func SetPageHeaders(h http.Header) {
	for k, v := range pageHeaders {
		h.Set(k, v)
	}
}

// page is the login page's content.
type page struct {
	SignedInAs string // the username of the End-User signed in, if any
	Username   string // the username to fill the form with
	Error      string
}

var pageTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{if .SignedInAs}}Signed in{{else}}Sign in{{end}}</title>
</head>
<body>
<main>
{{- if .SignedInAs}}
<p>Signed in as {{.SignedInAs}}.</p>
{{- else}}
<h1>Sign in</h1>
{{- with .Error}}
<p role="alert">{{.}}</p>
{{- end}}
<form method="post">
<p><label>Username <input name="username" autocomplete="username" required value="{{.Username}}"></label></p>
<p><label>Password <input name="password" type="password" autocomplete="current-password" required></label></p>
<p><button type="submit">Sign in</button></p>
</form>
{{- end}}
</main>
</body>
</html>
`))

// baseSessions is the session manager every Sessions' is copied from.
// Only scs.New can make one, since it alone sets a manager's private
// context key, and it also installs an in-memory store with a goroutine
// that cleans it for the life of the process. Making the manager once,
// when the package is initialized, keeps that to one idle goroutine per
// process, outside any testing/synctest bubble, rather than one per
// Sessions. NewSessions replaces the store, so the in-memory one stays
// empty.
var baseSessions = scs.New()

// Sessions keeps the Login Sessions of the End-Users of a registry, in
// PostgreSQL. It is safe for concurrent use.
type Sessions struct {
	manager  *scs.SessionManager
	store    *store
	registry *registry.Registry
}

// NewSessions returns the Login Sessions of the End-Users of reg, kept in
// the database behind pool.
func NewSessions(pool *pgxpool.Pool, reg *registry.Registry) *Sessions {
	st := &store{queries: queries.New(pool)}
	m := new(scs.SessionManager)
	*m = *baseSessions
	m.Store = st
	m.IdleTimeout = idleTimeout
	m.Lifetime = lifetime
	m.HashTokenInStore = true
	m.Cookie.Name = cookieName
	m.Cookie.Path = "/"
	m.Cookie.Secure = true
	m.Cookie.HttpOnly = true
	m.Cookie.SameSite = http.SameSiteLaxMode
	return &Sessions{manager: m, store: st, registry: reg}
}

// Authentication is an End-User's authentication, as a Login Session
// records it.
type Authentication struct {
	EndUser *registry.EndUser
	Time    time.Time // when the End-User authenticated
}

// load returns r with its Login Session, if it has one, or a new empty
// one, in its context.
func (s *Sessions) load(r *http.Request) (*http.Request, error) {
	var token string
	if c, err := r.Cookie(cookieName); err == nil {
		token = c.Value
	}
	ctx, err := s.manager.Load(r.Context(), token)
	if err != nil {
		return nil, fmt.Errorf("load the Login Session: %w", err)
	}
	return r.WithContext(ctx), nil
}

// save stores the request's Login Session, if it has changed, and sets its
// cookie. It must run before anything of the response is written.
//
// A Login Session changes at login, and on every request that loads one,
// since each request moves its idle expiry.
func (s *Sessions) save(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	if s.manager.Status(ctx) != scs.Modified {
		return nil
	}
	token, expiry, err := s.manager.Commit(ctx)
	if err != nil {
		return fmt.Errorf("save the Login Session: %w", err)
	}
	s.manager.WriteSessionCookie(ctx, w, token, expiry)
	return nil
}

// endUser returns the End-User signed in by the request's Login Session.
// A Login Session for a Subject the registry no longer lists signs no one
// in.
func (s *Sessions) endUser(r *http.Request) (*registry.EndUser, bool) {
	sub := s.manager.GetString(r.Context(), subjectKey)
	if sub == "" {
		return nil, false
	}
	return s.registry.EndUser(sub)
}

// Handler serves the login page, by GET, and the login form's submission,
// by POST, at path. A login from a page whose URL has a query sends the
// browser on to continuePath with the same query: that is how an
// authorization request, sent to the login page with its parameters,
// resumes after login, and the login is recorded as made for that request
// (see [Interaction]). Such a page shows the form even to a browser
// already signed in, and fills its username with the request's
// login_hint. Any other login sends the browser back to the page. It logs
// to logger any error that ends a request.
func (s *Sessions) Handler(path, continuePath string, logger *slog.Logger) http.Handler {
	h := &handler{path: path, continuePath: continuePath, sessions: s, logger: logger}
	return http.NewCrossOriginProtection().Handler(h)
}

type handler struct {
	path         string // the page's request path
	continuePath string // where a login from a page with a query goes on to
	sessions     *Sessions
	logger       *slog.Logger
}

// ServeHTTP loads the request's Login Session itself, rather than through
// scs's LoadAndSave, which saves the Login Session when the response is
// first written and, if saving fails, writes its error response and then
// the page after it. Here every response is preceded by save, which
// answers 500 alone if saving fails.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	SetPageHeaders(w.Header())
	w.Header().Add("Vary", "Cookie")
	loaded, err := h.sessions.load(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	r = loaded

	if r.Method == http.MethodPost {
		h.login(w, r)
		return
	}
	// The username the authorization request suggests, if any (OpenID
	// Connect Core 1.0 §3.1.2.1).
	p := page{Username: r.URL.Query().Get("login_hint")}
	// A page for an authorization request always shows the form: the
	// authorization endpoint sends a signed-in End-User here only to log
	// in again.
	if u, ok := h.sessions.endUser(r); ok && r.URL.RawQuery == "" {
		p.SignedInAs = u.Username
	}
	h.render(w, r, p)
}

// login authenticates the End-User whose username and password the form
// carries, from the request body only, and on success starts a Login
// Session under a new token and sends the browser on.
func (h *handler) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormSize)
	if err := r.ParseForm(); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	username := r.PostForm.Get("username")
	u, ok := h.sessions.registry.AuthenticateEndUser(username, r.PostForm.Get("password"))
	if !ok {
		h.render(w, r, page{Username: username, Error: failedLogin})
		return
	}

	ctx := r.Context()
	m := h.sessions.manager
	if err := m.RenewToken(ctx); err != nil {
		h.fail(w, r, fmt.Errorf("renew the Login Session token: %w", err))
		return
	}
	if err := m.Clear(ctx); err != nil {
		h.fail(w, r, fmt.Errorf("clear the Login Session: %w", err))
		return
	}
	m.Put(ctx, subjectKey, u.Subject)
	m.Put(ctx, authTimeKey, time.Now().Unix())
	if r.URL.RawQuery != "" {
		// The login is for the authorization request the page was shown
		// for, which counts it as the new login it may ask for (see
		// Interaction).
		m.Put(ctx, loginForKey, requestKey(r.URL.RawQuery))
	}
	h.continueAfterLogin(w, r)
}

// continueAfterLogin saves the Login Session and sends the browser on: to
// continuePath with the page's query, if it has one, and back to the page
// otherwise.
func (h *handler) continueAfterLogin(w http.ResponseWriter, r *http.Request) {
	if err := h.sessions.save(w, r); err != nil {
		h.fail(w, r, err)
		return
	}
	// The query goes on unchanged to a fixed path on this origin, so it
	// cannot send the browser anywhere else. 303, not 307, so that a
	// password in this request's body is not sent on (RFC 9700 §4.12).
	next := h.path
	if r.URL.RawQuery != "" {
		next = h.continuePath + "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, next, http.StatusSeeOther) //nolint:gosec // G710: next is a fixed path on this origin; the query cannot change it.
}

func (h *handler) render(w http.ResponseWriter, r *http.Request, p page) {
	var buf bytes.Buffer
	if err := pageTemplate.Execute(&buf, p); err != nil {
		h.fail(w, r, fmt.Errorf("render login page: %w", err))
		return
	}
	if err := h.sessions.save(w, r); err != nil {
		h.fail(w, r, err)
		return
	}
	_, _ = buf.WriteTo(w) // A failed write means the browser has gone.
}

func (h *handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	h.logger.ErrorContext(r.Context(), "login page", "error", err)
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}
