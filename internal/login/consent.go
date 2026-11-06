package login

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palebluedot4/pulsar/internal/login/internal/queries"
)

// ConsentPath is the path, relative to the issuer, that the consent form
// is submitted to.
const ConsentPath = "/consent"

// Consents keeps each End-User's Consents, in PostgreSQL. It is safe for
// concurrent use.
type Consents struct {
	queries *queries.Queries
}

// NewConsents returns the Consents kept in the database behind pool.
func NewConsents(pool *pgxpool.Pool) *Consents {
	return &Consents{queries: queries.New(pool)}
}

// Covers reports whether the End-User whose Subject is subject has allowed
// the Client clientID every one of scopes.
func (c *Consents) Covers(ctx context.Context, subject, clientID string, scopes []string) (bool, error) {
	allowed, err := c.queries.FindConsent(ctx, queries.FindConsentParams{Subject: subject, ClientID: clientID})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("find the Consent: %w", err)
	}
	for _, s := range scopes {
		if !slices.Contains(allowed, s) {
			return false, nil
		}
	}
	return true, nil
}

// OfflineAccess is the scope value by which a Client asks for offline
// access (OpenID Connect Core 1.0 §11). No Consent includes it, so that
// every request for it asks the End-User.
const OfflineAccess = "offline_access"

// Allow adds scopes, except [OfflineAccess], to what the End-User whose
// Subject is subject has allowed the Client clientID.
func (c *Consents) Allow(ctx context.Context, subject, clientID string, scopes []string) error {
	scopes = slices.DeleteFunc(slices.Clone(scopes), func(s string) bool { return s == OfflineAccess })
	if err := c.queries.AddToConsent(ctx, queries.AddToConsentParams{Subject: subject, ClientID: clientID, Scopes: scopes}); err != nil {
		return fmt.Errorf("add to the Consent: %w", err)
	}
	return nil
}

// ConsentPage is the content of the consent page.
type ConsentPage struct {
	ClientID string // the Client that asks
	// Subject and Username are those of the End-User signed in, whom the
	// page asks. A decision counts only for that Subject.
	Subject  string
	Username string
	Scopes   []Scope // the scopes the Client asks for
	// Action is where the form is submitted: the consent form's path, with
	// the authorization request's parameters as its query.
	Action string
}

// endUserField is the consent form's field that carries the Subject of
// the End-User the page was shown for.
const endUserField = "end_user"

// consentPageData is what the consent page's template reads: the page,
// and the form's names and values, from their one definition here.
type consentPageData struct {
	ConsentPage
	EndUserField string
	Allow, Deny  string
}

// Scope is a scope value the consent page lists, with what it releases,
// as the page says it to the End-User.
type Scope struct {
	Value       string
	Description string
}

var consentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Allow access</title>
</head>
<body>
<main>
<h1>Allow access</h1>
<p>Signed in as {{.Username}}.</p>
<p>The client <strong id="client">{{.ClientID}}</strong> asks to receive:</p>
<ul>
{{- range .Scopes}}
<li><code>{{.Value}}</code>: {{.Description}}</li>
{{- end}}
</ul>
<form method="post" action="{{.Action}}">
<input type="hidden" name="{{.EndUserField}}" value="{{.Subject}}">
<p><button type="submit" name="decision" value="{{.Allow}}">Allow</button>
<button type="submit" name="decision" value="{{.Deny}}">Deny</button></p>
</form>
</main>
</body>
</html>
`))

// WriteConsentPage writes the consent page p, with the headers of every
// page pulsar serves. It must be called after the Login Session is saved.
func WriteConsentPage(w http.ResponseWriter, p ConsentPage) error {
	data := consentPageData{
		ConsentPage:  p,
		EndUserField: endUserField,
		Allow:        decisionValues[Allowed],
		Deny:         decisionValues[Denied],
	}
	var buf bytes.Buffer
	if err := consentTemplate.Execute(&buf, data); err != nil {
		return fmt.Errorf("render the consent page: %w", err)
	}
	SetPageHeaders(w.Header())
	w.WriteHeader(http.StatusOK)
	_, _ = buf.WriteTo(w) // A failed write means the browser has gone.
	return nil
}

// ConsentHandler serves the consent form's submission, by POST. The
// form's URL carries the authorization request's parameters as its query,
// and its body the decision, allow or deny, and the Subject of the
// End-User the page was shown for. The decision is recorded in the Login
// Session for that request (see [Interaction]), if that End-User is still
// the one signed in, and the browser is sent on to continuePath with the
// same query, where the authorization endpoint acts on it. Otherwise
// nothing is recorded, and the authorization endpoint asks again, or
// sends a browser without a Login Session to log in.
//
// The form refuses cross-origin submissions, through
// [http.CrossOriginProtection], so that another site cannot decide for an
// End-User.
func (s *Sessions) ConsentHandler(continuePath string, logger *slog.Logger) http.Handler {
	h := &consentHandler{continuePath: continuePath, sessions: s, logger: logger}
	return http.NewCrossOriginProtection().Handler(h)
}

type consentHandler struct {
	continuePath string
	sessions     *Sessions
	logger       *slog.Logger
}

func (h *consentHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, maxFormSize)
	if err := r.ParseForm(); err != nil || r.URL.RawQuery == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	decision, ok := parseDecision(r.PostForm.Get("decision"))
	if !ok {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	loaded, err := h.sessions.load(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	r = loaded
	if u, ok := h.sessions.endUser(r); ok && u.Subject == r.PostForm.Get(endUserField) {
		h.sessions.decide(r, r.URL.RawQuery, decision)
	}
	if err := h.sessions.save(w, r); err != nil {
		h.fail(w, r, err)
		return
	}
	// As after login: the query goes on unchanged to a fixed path on this
	// origin, by 303, so that the browser retrieves it by GET.
	http.Redirect(w, r, h.continuePath+"?"+r.URL.RawQuery, http.StatusSeeOther) //nolint:gosec // G710: continuePath is a fixed path on this origin; the query cannot change it.
}

func (h *consentHandler) fail(w http.ResponseWriter, r *http.Request, err error) {
	h.logger.ErrorContext(r.Context(), "consent form", "error", err)
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}
