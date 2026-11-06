package oidc

import (
	"bytes"
	"context"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/palebluedot4/pulsar/internal/login"
	"github.com/palebluedot4/pulsar/internal/oidc/internal/queries"
	"github.com/palebluedot4/pulsar/internal/registry"
)

// supportedScopes are the scope values pulsar grants. A Client may request
// others; they are ignored, as RFC 6749 §3.3 allows.
var supportedScopes = []string{"openid", "profile", "email", "address", "phone"}

// authorizationParams are the parameters of an authorization request that
// pulsar reads. Every other parameter is ignored (RFC 6749 §3.1).
var authorizationParams = []string{
	"client_id", "redirect_uri", "response_type", "response_mode",
	"scope", "state", "nonce", "request", "request_uri",
}

// Error codes of an authorization error response (RFC 6749 §4.1.2.1,
// OpenID Connect Core 1.0 §3.1.2.6).
const (
	errInvalidRequest          = "invalid_request"
	errUnsupportedResponseType = "unsupported_response_type"
	errInvalidScope            = "invalid_scope"
	errServerError             = "server_error"
	errRequestNotSupported     = "request_not_supported"
	errRequestURINotSupported  = "request_uri_not_supported"
)

var errorPageTemplate = template.Must(template.New("error").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Invalid request</title>
</head>
<body>
<main>
<h1>Invalid request</h1>
<p>{{.}}</p>
</main>
</body>
</html>
`))

// HandleAuthorization serves the authorization endpoint, by GET and POST
// (OpenID Connect Core 1.0 §3.1.2.1). An End-User without a Login Session
// is sent to the login page at loginPath with the request's parameters,
// and returns here with them after login.
func (p *Provider) HandleAuthorization(loginPath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.authorize(w, r, loginPath)
	})
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request, loginPath string) {
	// The query of a GET, or the form-encoded body of a POST (OpenID
	// Connect Core 1.0 §3.1.2.1).
	params, err := readParams(w, r)
	if err != nil {
		p.errorPage(w, "The authorization request could not be read.")
		return
	}

	// Until the Client and redirect URI are known to be valid, an error
	// is shown to the End-User and never redirected (RFC 6749 §4.1.2.1).
	clientID := params["client_id"]
	if len(clientID) != 1 {
		p.errorPage(w, "The authorization request must name one client_id.")
		return
	}
	client, ok := p.registry.Client(clientID[0])
	if !ok {
		p.errorPage(w, "The authorization request names a client_id that is not registered.")
		return
	}
	i := -1
	if v := params["redirect_uri"]; len(v) == 1 {
		i = slices.Index(client.RedirectURIs, v[0])
	}
	if i < 0 {
		p.errorPage(w, "The authorization request's redirect_uri is not one the client registered.")
		return
	}
	// The registered URI, which the request's equals, is the one
	// redirected to.
	redirectURI := client.RedirectURIs[i]

	resp := authorizationResponse{redirectURI: redirectURI, issuer: p.issuer.String()}
	if state := params["state"]; len(state) > 0 {
		resp.state = state[0]
	}
	req, errCode, errDesc := parseAuthorizationRequest(client, redirectURI, params)
	if errCode != "" {
		resp.redirectError(w, r, errCode, errDesc)
		return
	}

	auth, ok, err := p.sessions.Authenticated(w, r) //nolint:contextcheck // r carries the request's context, which Authenticated uses.
	if err != nil {
		p.logger.ErrorContext(r.Context(), "authorization endpoint", "error", err)
		resp.redirectError(w, r, errServerError, "")
		return
	}
	if !ok {
		// 303, so that a request sent by POST is retrieved by GET; the
		// parameters go in the query, to a fixed path on this origin.
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, loginPath+"?"+params.Encode(), http.StatusSeeOther) //nolint:gosec // G710: loginPath is a fixed path on this origin; the query cannot change it.
		return
	}

	code, err := p.issueCode(r.Context(), req, auth)
	if err != nil {
		p.logger.ErrorContext(r.Context(), "issue authorization code", "error", err)
		resp.redirectError(w, r, errServerError, "")
		return
	}
	resp.redirect(w, r, url.Values{"code": {code}})
}

// authorizationRequest is an authorization request whose Client and
// redirect URI are valid and whose other parameters pulsar accepts.
type authorizationRequest struct {
	client      *registry.Client
	redirectURI string
	scopes      []string // the scope values granted
	nonce       string
}

// parseAuthorizationRequest checks the parameters of an authorization
// request for client, with redirectURI, one it registered, and returns the request,
// or the error code and description to redirect with.
func parseAuthorizationRequest(client *registry.Client, redirectURI string, params url.Values) (req authorizationRequest, errCode, errDesc string) {
	if name, ok := repeated(params, authorizationParams); ok {
		return req, errInvalidRequest, "The parameter " + name + " is repeated."
	}
	switch {
	case params.Has("request"):
		return req, errRequestNotSupported, "Request objects are not supported."
	case params.Has("request_uri"):
		return req, errRequestURINotSupported, "Request objects are not supported."
	}

	switch responseType := params.Get("response_type"); responseType {
	case "code":
	case "":
		return req, errInvalidRequest, "The parameter response_type is required."
	default:
		return req, errUnsupportedResponseType, "Only the response_type code is supported."
	}
	if mode := params.Get("response_mode"); mode != "" && mode != "query" {
		return req, errInvalidRequest, "Only the response_mode query is supported."
	}

	var scopes []string
	for s := range strings.FieldsSeq(params.Get("scope")) {
		if slices.Contains(supportedScopes, s) && !slices.Contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}
	if !slices.Contains(scopes, "openid") {
		return req, errInvalidScope, "The scope must include openid."
	}

	return authorizationRequest{
		client:      client,
		redirectURI: redirectURI,
		scopes:      scopes,
		nonce:       params.Get("nonce"),
	}, "", ""
}

// issueCode stores and returns a new authorization code for req, for the
// End-User of auth.
func (p *Provider) issueCode(ctx context.Context, req authorizationRequest, auth login.Authentication) (string, error) {
	now := time.Now()
	// Issuing a code is when expired ones are deleted. A failure leaves
	// them for the next and does not fail this one.
	if err := p.queries.DeleteExpiredAuthorizationCodes(ctx, now); err != nil {
		p.logger.ErrorContext(ctx, "delete expired authorization codes", "error", err)
	}
	code, hash := newCode()
	err := p.queries.InsertAuthorizationCode(ctx, queries.InsertAuthorizationCodeParams{
		CodeHash:    hash,
		ClientID:    req.client.ID,
		RedirectUri: req.redirectURI,
		Subject:     auth.EndUser.Subject,
		Scopes:      req.scopes,
		Nonce:       req.nonce,
		AuthTime:    auth.Time,
		Expiry:      now.Add(codeLifetime),
	})
	if err != nil {
		return "", err
	}
	return code, nil
}

// authorizationResponse sends the authorization response, success or
// error, to a Client's redirect URI.
type authorizationResponse struct {
	redirectURI string
	state       string
	issuer      string
}

// redirect sends the browser to the redirect URI with params, and with
// state and iss (RFC 6749 §4.1.2, RFC 9207 §2) added. The parameters are
// appended to any query the redirect URI has, which is kept as registered
// (RFC 6749 §3.1.2).
func (a authorizationResponse) redirect(w http.ResponseWriter, r *http.Request, params url.Values) {
	if a.state != "" {
		params.Set("state", a.state)
	}
	params.Set("iss", a.issuer)
	sep := "?"
	switch {
	case strings.HasSuffix(a.redirectURI, "?") || strings.HasSuffix(a.redirectURI, "&"):
		sep = ""
	case strings.Contains(a.redirectURI, "?"):
		sep = "&"
	}
	// The response carries a code, which no cache may keep. 303, as RFC
	// 9700 §4.12 advises, so that a request sent by POST is not sent on.
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, a.redirectURI+sep+params.Encode(), http.StatusSeeOther)
}

// redirectError sends the browser to the redirect URI with an error
// response (RFC 6749 §4.1.2.1). desc, if any, is fixed text that never
// repeats the request.
func (a authorizationResponse) redirectError(w http.ResponseWriter, r *http.Request, code, desc string) {
	params := url.Values{"error": {code}}
	if desc != "" {
		params.Set("error_description", desc)
	}
	a.redirect(w, r, params)
}

// errorPage tells the End-User that the authorization request is invalid,
// without redirecting. msg is fixed text that never repeats the request.
func (p *Provider) errorPage(w http.ResponseWriter, msg string) {
	var buf bytes.Buffer
	if err := errorPageTemplate.Execute(&buf, msg); err != nil {
		// The template takes one string and always executes.
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	login.SetPageHeaders(w.Header())
	w.WriteHeader(http.StatusBadRequest)
	_, _ = buf.WriteTo(w) // A failed write means the browser has gone.
}
