package login

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/palebluedot4/pulsar/internal/registry"
)

// LogoutPage is the content of the page that asks the End-User to confirm
// a logout.
type LogoutPage struct {
	// ClientID is the Client that sent the End-User, or "" if it is not
	// known.
	ClientID string
	// Known reports whether the page is shown for the End-User whose
	// Subject and Username these are, or for no one if they are "": a
	// confirmation then counts only for that Subject. A page not Known is
	// shown for whoever is signed in when it is answered, and names no one.
	Known    bool
	Subject  string
	Username string
	// Action is where the form is submitted: the confirmation's path.
	Action string
	// Request is the logout request's parameters, which the form submits
	// again in its body, so that no URL carries them.
	Request map[string]string
}

// The values the confirmation form submits for the decisions an End-User
// can make there: to log out, or to stay signed in.
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
{{- range $name, $value := .Request}}
<input type="hidden" name="{{$name}}" value="{{$value}}">
{{- end}}
{{- if .Known}}
<input type="hidden" name="{{.EndUserField}}" value="{{.Subject}}">
{{- end}}
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
// to return to: that the End-User is signed out, if no Login Session is
// left, or still signed in, if they declined and theirs is kept. It must
// be called after the Login Session is ended or saved.
func WriteLogoutOutcomePage(w http.ResponseWriter, signedOut bool) error {
	return writePage(w, logoutOutcomeTemplate, signedOut)
}

// LogoutForm is a submission of the confirmation form.
type LogoutForm struct {
	// Confirmed reports whether the End-User chose to log out.
	Confirmed bool
	// ShownFor is the Subject of the End-User the page was shown for, or ""
	// if it was shown for no one; nil if it was shown for whoever is signed
	// in when it is answered (see [LogoutPage]).
	ShownFor *string
	// Values are every value of the form's body, the logout request's
	// parameters among them.
	Values url.Values
}

// ReadLogoutForm reads the confirmation form from the body of r. It reports
// false if the body is not such a form.
func ReadLogoutForm(w http.ResponseWriter, r *http.Request) (LogoutForm, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormSize)
	if err := r.ParseForm(); err != nil {
		return LogoutForm{}, false
	}
	f := LogoutForm{Values: r.PostForm}
	if r.PostForm.Has(endUserField) {
		subject := r.PostForm.Get(endUserField)
		f.ShownFor = &subject
	}
	switch r.PostForm.Get("decision") {
	case logoutValue:
		f.Confirmed = true
	case stayValue:
	default:
		return LogoutForm{}, false
	}
	return f, true
}

// LogoutSession is the Login Session of a request to log out, if it has
// one.
type LogoutSession struct {
	sessions *Sessions
	r        *http.Request // carries the loaded Login Session
}

// LogoutSession loads r's Login Session, or a new empty one, for a request
// to log out.
func (s *Sessions) LogoutSession(r *http.Request) (*LogoutSession, error) {
	r, err := s.load(r)
	if err != nil {
		return nil, err
	}
	return &LogoutSession{sessions: s, r: r}, nil
}

// EndUser returns the End-User signed in, if anyone is.
func (l *LogoutSession) EndUser() (*registry.EndUser, bool) {
	return l.sessions.endUser(l.r)
}

// Save stores the Login Session, as a request that does not end it does,
// and writes its cookie to w. It must be called before anything of the
// response is written.
func (l *LogoutSession) Save(w http.ResponseWriter) error {
	return l.sessions.save(w, l.r)
}

// End deletes the Login Session, if there is one, and writes to w a cookie
// that removes it from the browser. It must be called before anything of
// the response is written.
func (l *LogoutSession) End(w http.ResponseWriter) error {
	ctx, m := l.r.Context(), l.sessions.manager
	if err := m.Destroy(ctx); err != nil {
		return fmt.Errorf("end the Login Session: %w", err)
	}
	m.WriteSessionCookie(ctx, w, "", time.Time{})
	return nil
}
