package oidc

import (
	"bytes"
	"html/template"
	"maps"
	"net/http"
	"net/url"
	"slices"

	"github.com/palebluedot4/pulsar/internal/login"
)

// autoSubmit is the form-post page's one script: it submits the page's
// form as soon as it runs. The page's Content-Security-Policy allows it by
// its hash, so the text here is the whole of the script element.
const autoSubmit = "document.forms[0].submit();"

// formPostTemplate is the form-post page (OAuth 2.0 Form Post Response
// Mode §2): a form whose action is the redirect URI and whose method is
// POST, with one hidden input for each parameter, which autoSubmit submits
// and whose button submits for a browser without script.
var formPostTemplate = template.Must(template.New("form_post").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Continue</title>
</head>
<body>
<main>
<form method="post" action="{{.Action}}">
{{- range .Params}}
<input type="hidden" name="{{.Name}}" value="{{.Value}}">
{{- end}}
<p><button type="submit">Continue</button></p>
</form>
</main>
<script>` + autoSubmit + `</script>
</body>
</html>
`))

// formPostHeaders are the form-post page's headers.
var formPostHeaders = login.NewScriptPage(autoSubmit)

// formPostPage is what formPostTemplate reads.
type formPostPage struct {
	Action string // a redirect URI the Client registered, one postable accepts
	Params []formPostParam
}

// formPostParam is one parameter the form posts.
type formPostParam struct {
	Name, Value string
}

// postable reports whether a browser can POST to redirectURI, a redirect
// URI the Client registered: whether its scheme is http or https. A
// browser hands a URI of any other scheme, such as a native app's
// (RFC 8252 §7.1), to the app that claims it, without a body, so a
// response sent there by form_post would never arrive.
func postable(redirectURI string) bool {
	u, err := url.Parse(redirectURI) // Parse lowercases the scheme.
	return err == nil && (u.Scheme == "https" || u.Scheme == "http")
}

// writeFormPost answers with the form-post page that posts params to
// redirectURI, which must be postable, under the headers of pulsar's
// other pages: never cached (OAuth 2.0 Form Post Response Mode §2) and
// never framed (RFC 9700 §4.16), with the same Content-Security-Policy but
// for allowing autoSubmit.
func writeFormPost(w http.ResponseWriter, redirectURI string, params url.Values) {
	page := formPostPage{Action: redirectURI}
	for _, name := range slices.Sorted(maps.Keys(params)) {
		for _, v := range params[name] {
			page.Params = append(page.Params, formPostParam{Name: name, Value: v})
		}
	}
	var buf bytes.Buffer
	if err := formPostTemplate.Execute(&buf, page); err != nil {
		// The template takes strings only and always executes.
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	formPostHeaders.SetHeaders(w.Header())
	w.WriteHeader(http.StatusOK)
	_, _ = buf.WriteTo(w) // A failed write means the browser has gone.
}
