package login

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/palebluedot4/pulsar/internal/registry"
)

// LogoutPage is the content of the page that asks the End-User to confirm
// a logout.
type LogoutPage struct {
	// ClientID is the Client that sent the End-User, or "" if it is not
	// known.
	ClientID string
	// Subject and Username are those of the End-User signed in, or "" if
	// no one is. A confirmation counts only for that Subject.
	Subject  string
	Username string
	// Action is where the form is submitted: the confirmation's path, with
	// the logout request's parameters as its query.
	Action string
}

// logoutValues are the values the confirmation form submits for the
// decisions an End-User can make there: to log out, or to stay signed in.
const (
	logoutValue = "logout"
	stayValue   = "stay"
)

// logoutPageData is what the confirmation page's template reads: the page,
// and the form's names and values, from their one definition here.
type logoutPageData struct {
	LogoutPage
	EndUserField string
	Logout, Stay string
}

var logoutTemplate = template.Must(template.New("logout").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign out</title>
</head>
<body>
<main>
<h1>Sign out</h1>
{{- if .Username}}
<p id="signed-in">Signed in as {{.Username}}.</p>
{{- end}}
{{- if .ClientID}}
<p>The client <strong id="client">{{.ClientID}}</strong> asks to sign you out of this provider.</p>
{{- else}}
<p>A client asks to sign you out of this provider.</p>
{{- end}}
<form method="post" action="{{.Action}}">
<input type="hidden" name="{{.EndUserField}}" value="{{.Subject}}">
<p><button type="submit" name="decision" value="{{.Logout}}">Sign out</button>
<button type="submit" name="decision" value="{{.Stay}}">Stay signed in</button></p>
</form>
</main>
</body>
</html>
`))

// WriteLogoutPage writes the confirmation page p, with the headers of
// every page pulsar serves. It must be called after the Login Session is
// saved.
func WriteLogoutPage(w http.ResponseWriter, p LogoutPage) error {
	return writePage(w, logoutTemplate, logoutPageData{
		LogoutPage:   p,
		EndUserField: endUserField,
		Logout:       logoutValue,
		Stay:         stayValue,
	})
}

var logoutOutcomeTemplate = template.Must(template.New("logout outcome").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{if .}}Signed out{{else}}Still signed in{{end}}</title>
</head>
<body>
<main>
<h1>{{if .}}Signed out{{else}}Still signed in{{end}}</h1>
<p id="outcome">{{if .}}You are signed out.{{else}}You are still signed in.{{end}}</p>
</main>
</body>
</html>
`))

// WriteLogoutOutcomePage writes the page that ends a logout with no Client
// to return to: that the End-User is signed out, or, if they declined,
// still signed in. It must be called after the Login Session is ended or
// saved.
func WriteLogoutOutcomePage(w http.ResponseWriter, signedOut bool) error {
	return writePage(w, logoutOutcomeTemplate, signedOut)
}

// writePage writes the page that t renders from data, with the headers of
// every page pulsar serves.
func writePage(w http.ResponseWriter, t *template.Template, data any) error {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return fmt.Errorf("render the %s page: %w", t.Name(), err)
	}
	SetPageHeaders(w.Header())
	w.WriteHeader(http.StatusOK)
	_, _ = buf.WriteTo(w) // A failed write means the browser has gone.
	return nil
}

// LogoutForm is a submission of the confirmation form.
type LogoutForm struct {
	// Confirmed reports whether the End-User chose to log out.
	Confirmed bool
	// Subject is that of the End-User the page was shown for, or "" if no
	// one was signed in.
	Subject string
}

// ReadLogoutForm reads the confirmation form from the body of r. It reports
// false if the body is not such a form.
func ReadLogoutForm(w http.ResponseWriter, r *http.Request) (LogoutForm, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormSize)
	if err := r.ParseForm(); err != nil {
		return LogoutForm{}, false
	}
	f := LogoutForm{Subject: r.PostForm.Get(endUserField)}
	switch r.PostForm.Get("decision") {
	case logoutValue:
		f.Confirmed = true
	case stayValue:
	default:
		return LogoutForm{}, false
	}
	return f, true
}

// Logout is the Login Session of a request to log out, if it has one.
type Logout struct {
	sessions *Sessions
	r        *http.Request // carries the loaded Login Session
}

// Logout loads r's Login Session, or a new empty one, for a request to log
// out.
func (s *Sessions) Logout(r *http.Request) (*Logout, error) {
	r, err := s.load(r)
	if err != nil {
		return nil, err
	}
	return &Logout{sessions: s, r: r}, nil
}

// EndUser returns the End-User signed in, if anyone is.
func (l *Logout) EndUser() (*registry.EndUser, bool) {
	return l.sessions.endUser(l.r)
}

// Save stores the Login Session, as a request that does not end it does,
// and writes its cookie to w. It must be called before anything of the
// response is written.
func (l *Logout) Save(w http.ResponseWriter) error {
	return l.sessions.save(w, l.r)
}

// End deletes the Login Session, if there is one, and writes to w a cookie
// that removes it from the browser. It must be called before anything of
// the response is written.
func (l *Logout) End(w http.ResponseWriter) error {
	ctx, m := l.r.Context(), l.sessions.manager
	if err := m.Destroy(ctx); err != nil {
		return fmt.Errorf("end the Login Session: %w", err)
	}
	m.WriteSessionCookie(ctx, w, "", time.Time{})
	return nil
}
