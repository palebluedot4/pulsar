// Package login serves the login page and keeps the Login Session that a
// successful login starts.
//
// A Login Session is kept by scs, server-side in PostgreSQL. Its cookie
// has the __Host- prefix and is Secure and HttpOnly, and SameSite=Lax
// rather than Strict, because Strict would drop it on the top-level
// cross-site navigation that carries an authorization request. A Login
// Session ends 30 minutes after its last request or 10 hours after login,
// whichever comes first, and its token is replaced at each login, so that
// a token planted in a browser beforehand is worthless afterward.
//
// The login form refuses cross-origin submissions, through
// [http.CrossOriginProtection], and the page may not be framed.
package login

import (
	"bytes"
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

// baseSessions is the session manager every Handler's is copied from.
// Only scs.New can make one, since it alone sets a manager's private
// context key, and it also installs an in-memory store with a goroutine
// that cleans it for the life of the process. Making the manager once,
// when the package is initialized, keeps that to one idle goroutine per
// process, outside any testing/synctest bubble, rather than one per
// Handler. Handler replaces the store, so the in-memory one stays empty.
var baseSessions = scs.New()

// Handler serves the login page, by GET, and the login form's submission,
// by POST, at path, for the End-Users of reg, keeping Login Sessions in
// the database behind pool. It logs to logger any error that ends a
// request.
func Handler(path string, pool *pgxpool.Pool, reg *registry.Registry, logger *slog.Logger) http.Handler {
	st := &store{queries: queries.New(pool)}
	sessions := new(scs.SessionManager)
	*sessions = *baseSessions
	sessions.Store = st
	sessions.IdleTimeout = idleTimeout
	sessions.Lifetime = lifetime
	sessions.HashTokenInStore = true
	sessions.Cookie.Name = cookieName
	sessions.Cookie.Path = "/"
	sessions.Cookie.Secure = true
	sessions.Cookie.HttpOnly = true
	sessions.Cookie.SameSite = http.SameSiteLaxMode
	sessions.ErrorFunc = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.ErrorContext(r.Context(), "login session", "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
	h := &handler{path: path, sessions: sessions, store: st, registry: reg, logger: logger}
	return http.NewCrossOriginProtection().Handler(sessions.LoadAndSave(h))
}

type handler struct {
	path     string // the page's request path
	sessions *scs.SessionManager
	store    *store
	registry *registry.Registry
	logger   *slog.Logger
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for k, v := range pageHeaders {
		w.Header().Set(k, v)
	}
	if r.Method == http.MethodPost {
		h.login(w, r)
		return
	}
	var p page
	if u, ok := h.endUser(r); ok {
		p.SignedInAs = u.Username
	}
	h.render(w, r, p)
}

// login authenticates the End-User whose username and password the form
// carries, from the request body only, and on success starts a Login
// Session under a new token and sends the browser back to the page.
func (h *handler) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormSize)
	if err := r.ParseForm(); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	username := r.PostForm.Get("username")
	u, ok := h.registry.AuthenticateEndUser(username, r.PostForm.Get("password"))
	if !ok {
		h.render(w, r, page{Username: username, Error: failedLogin})
		return
	}

	ctx := r.Context()
	if err := h.sessions.RenewToken(ctx); err != nil {
		h.fail(w, r, "renew the Login Session token", err)
		return
	}
	if err := h.sessions.Clear(ctx); err != nil {
		h.fail(w, r, "clear the Login Session", err)
		return
	}
	h.sessions.Put(ctx, subjectKey, u.Subject)
	h.sessions.Put(ctx, authTimeKey, time.Now().Unix())
	// A login is rare next to the requests a Login Session serves, so it
	// is when Login Sessions that have ended are deleted. A failure leaves them
	// for the next login and does not fail this one.
	if err := h.store.deleteEnded(ctx); err != nil {
		h.logger.ErrorContext(ctx, "delete ended login sessions", "error", err)
	}
	http.Redirect(w, r, h.path, http.StatusSeeOther)
}

// endUser returns the End-User signed in by the request's Login Session.
// A Login Session for a Subject the registry no longer lists signs no one
// in.
func (h *handler) endUser(r *http.Request) (*registry.EndUser, bool) {
	sub := h.sessions.GetString(r.Context(), subjectKey)
	if sub == "" {
		return nil, false
	}
	return h.registry.EndUser(sub)
}

func (h *handler) render(w http.ResponseWriter, r *http.Request, p page) {
	var buf bytes.Buffer
	if err := pageTemplate.Execute(&buf, p); err != nil {
		h.fail(w, r, "render login page", err)
		return
	}
	_, _ = buf.WriteTo(w) // A failed write means the browser has gone.
}

func (h *handler) fail(w http.ResponseWriter, r *http.Request, msg string, err error) {
	h.logger.ErrorContext(r.Context(), msg, "error", err)
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}
