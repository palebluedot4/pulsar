package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/palebluedot4/pulsar/internal/login"
	"github.com/palebluedot4/pulsar/internal/oidc/internal/queries"
	"github.com/palebluedot4/pulsar/internal/registry"
)

// supportedScopes are the scope values pulsar supports, each with what it
// releases, as the consent page says, in the order the discovery document
// lists them. A Client may request others; they are ignored, as RFC 6749
// §3.3 allows.
var supportedScopes = []login.Scope{
	{Value: "openid", Description: "your identifier at this provider"},
	{Value: "profile", Description: "your name and other profile details"},
	{Value: "email", Description: "your email address"},
	{Value: "address", Description: "your postal address"},
	{Value: "phone", Description: "your phone number"},
}

// scopeValues returns the values of scopes.
func scopeValues(scopes []login.Scope) []string {
	values := make([]string, len(scopes))
	for i, s := range scopes {
		values[i] = s.Value
	}
	return values
}

// supportedScope returns the scope whose value is value, if pulsar
// supports it.
func supportedScope(value string) (login.Scope, bool) {
	i := slices.IndexFunc(supportedScopes, func(s login.Scope) bool { return s.Value == value })
	if i < 0 {
		return login.Scope{}, false
	}
	return supportedScopes[i], true
}

// authorizationParams are the parameters of an authorization request that
// pulsar reads. Every other parameter is ignored (RFC 6749 §3.1).
var authorizationParams = []string{
	"client_id", "redirect_uri", "response_type", "response_mode",
	"scope", "state", "nonce", "request", "request_uri",
	"prompt", "max_age", "login_hint", "id_token_hint",
	"code_challenge", "code_challenge_method",
}

// Error codes of an authorization error response (RFC 6749 §4.1.2.1,
// OpenID Connect Core 1.0 §3.1.2.6).
const (
	errInvalidRequest          = "invalid_request"
	errAccessDenied            = "access_denied"
	errLoginRequired           = "login_required"
	errConsentRequired         = "consent_required"
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

// pagePaths are the paths, on this origin, of the pages the authorization
// endpoint sends an End-User to.
type pagePaths struct {
	login   string // the login page
	consent string // the consent form's submission
}

// HandleAuthorization serves the authorization endpoint, by GET and POST
// (OpenID Connect Core 1.0 §3.1.2.1). An End-User without a Login Session
// is sent to the login page at loginPath with the request's parameters,
// and returns here with them after login. An End-User whose Consent does
// not cover the request is shown the consent page, whose form, submitted
// to consentPath, returns here with them too.
func (p *Provider) HandleAuthorization(loginPath, consentPath string) http.Handler {
	paths := pagePaths{login: loginPath, consent: consentPath}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.authorize(w, r, paths)
	})
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request, paths pagePaths) {
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
	req, errCode, errDesc := parseAuthorizationRequest(client, redirectURI, p.issuer.String(), params)
	if errCode != "" {
		resp.redirectError(w, r, errCode, errDesc)
		return
	}

	// The parameters as the login page and the consent form carry them,
	// and as the Login Session keys what the End-User did for them.
	query := params.Encode()

	// A request a Client sends by POST from its own site arrives without
	// the SameSite=Lax Login Session cookie. It is sent back here by GET,
	// once, with the same parameters: a top-level navigation, on which the
	// browser sends the cookie, so that a signed-in End-User is found, with
	// prompt=none too. A GET is answered as it comes. 303, so that the
	// browser retrieves it by GET.
	if r.Method == http.MethodPost && !p.sessions.HasCookie(r) {
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, AuthorizationPath(p.issuer)+"?"+query, http.StatusSeeOther) //nolint:gosec // G710: the endpoint's own path, on this origin; the query cannot change it.
		return
	}

	ctx := r.Context()
	inter, err := p.sessions.Interaction(r, query) //nolint:contextcheck // r carries the request's context, which Interaction uses.
	if err != nil {
		p.logger.ErrorContext(ctx, "authorization endpoint", "error", err)
		resp.redirectError(w, r, errServerError, "")
		return
	}
	// respond saves the Login Session, which must precede any part of the
	// response, and then answers with answer.
	respond := func(answer func()) { //nolint:contextcheck // Save uses the context of r, which Interaction keeps.
		if err := inter.Save(w); err != nil {
			p.logger.ErrorContext(ctx, "authorization endpoint", "error", err)
			resp.redirectError(w, r, errServerError, "")
			return
		}
		answer()
	}
	// fail logs err, a failure of pulsar's own, and tells the Client. The
	// request ends there, so what the Login Session records for it is
	// removed, as long as the Login Session can still be saved, so that a
	// decision made for it does not answer the same request sent again.
	fail := func(err error) {
		p.logger.ErrorContext(ctx, "authorization endpoint", "error", err)
		inter.Finish()
		respond(func() { resp.redirectError(w, r, errServerError, "") })
	}
	// ask shows the End-User a page, with show; but with prompt=none, no
	// page is shown, and what the page would ask for is answered with the
	// error code errCode instead (OpenID Connect Core 1.0 §3.1.2.1,
	// §3.1.2.6). pulsar asks for nothing but a login and a Consent, so it
	// never needs interaction_required.
	ask := func(errCode, desc string, show func()) {
		if req.prompts("none") {
			respond(func() { resp.redirectError(w, r, errCode, desc) })
			return
		}
		respond(show)
	}
	toLogin := func() {
		// 303, so that a request sent by POST is retrieved by GET; the
		// parameters go in the query, to a fixed path on this origin.
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, paths.login+"?"+query, http.StatusSeeOther) //nolint:gosec // G710: the login page's path is fixed, on this origin; the query cannot change it.
	}

	auth, ok := inter.Authentication()
	if !ok {
		ask(errLoginRequired, "The End-User is not signed in.", toLogin)
		return
	}
	// A login the request asks for is one made on the login page for this
	// request (see login.Interaction and needsLogin). An End-User other
	// than the one id_token_hint names is sent to log in once; if that
	// login is not the named End-User's either, the request fails (OpenID
	// Connect Core 1.0 §3.1.2.1).
	subject := auth.EndUser.Subject
	otherEndUser := req.hintSubject != "" && req.hintSubject != subject
	fresh := inter.SignedInForRequest()
	decided := inter.Decision() != login.Undecided
	if (otherEndUser && !fresh) || req.needsLogin(auth.Time, time.Now(), fresh, fresh && decided) {
		ask(errLoginRequired, "The request requires a new login.", toLogin)
		return
	}
	if otherEndUser {
		inter.Finish()
		respond(func() {
			resp.redirectError(w, r, errLoginRequired, "The End-User signed in is not the one id_token_hint names.")
		})
		return
	}

	// An authorization decision, before anything is released (OpenID
	// Connect Core 1.0 §3.1.2.4): the one the End-User just made on the
	// consent page for this request, or else their Consent.
	switch inter.Decision() {
	case login.Denied:
		inter.Finish()
		respond(func() { resp.redirectError(w, r, errAccessDenied, "The End-User denied the request.") })
		return
	case login.Allowed:
		// A public Client's Consent is never consulted (see below), so it
		// is not kept.
		if !req.client.Public() {
			if err := p.consents.Allow(ctx, subject, req.client.ID, req.scopes); err != nil {
				fail(err)
				return
			}
		}
	case login.Undecided:
		// prompt=consent asks again, whatever the Consent covers. So does
		// every request from a public Client, which cannot authenticate:
		// another app could send its client_id, so a request is not
		// answered without the End-User's interaction (RFC 6749 §10.2), and
		// is processed as if no request had been approved before (RFC 8252
		// §8.6).
		covered := false
		if !req.prompts("consent") && !req.client.Public() {
			covered, err = p.consents.Covers(ctx, subject, req.client.ID, req.scopes)
			if err != nil {
				fail(err)
				return
			}
		}
		if !covered {
			ask(errConsentRequired, "The End-User has not consented to this request.", func() {
				page := login.ConsentPage{
					ClientID: req.client.ID,
					Subject:  subject,
					Username: auth.EndUser.Username,
					Action:   paths.consent + "?" + query,
				}
				for _, s := range req.scopes {
					scope, _ := supportedScope(s) // req.scopes holds supported scopes only.
					page.Scopes = append(page.Scopes, scope)
				}
				if err := login.WriteConsentPage(w, page); err != nil {
					p.logger.ErrorContext(ctx, "authorization endpoint", "error", err)
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}
			})
			return
		}
	}

	code, err := p.issueCode(ctx, req, auth)
	if err != nil {
		fail(err)
		return
	}
	inter.Finish()
	respond(func() { resp.redirect(w, r, url.Values{"code": {code}}) })
}

// authorizationRequest is an authorization request whose Client and
// redirect URI are valid and whose other parameters pulsar accepts.
type authorizationRequest struct {
	client      *registry.Client
	redirectURI string
	scopes      []string // the scope values granted
	nonce       string
	challenge   string   // the S256 code_challenge (RFC 7636 §4.3), or "" if it was not sent
	prompt      []string // the values of the prompt parameter (OpenID Connect Core 1.0 §3.1.2.1)
	maxAge      int64    // the max_age parameter, in seconds, or -1 if it sets no limit
	hintSubject string   // the Subject that id_token_hint names, if it was sent
}

// parseAuthorizationRequest checks the parameters of an authorization
// request for client, with redirectURI, one it registered, to the OP at
// issuer, and returns the request, or the error code and description to
// redirect with.
func parseAuthorizationRequest(client *registry.Client, redirectURI, issuer string, params url.Values) (req authorizationRequest, errCode, errDesc string) {
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

	// PKCE is required of a public Client only (ADR 0002), and S256 is the
	// only method; one not sent means plain (RFC 7636 §4.3). Each is
	// refused with invalid_request (RFC 7636 §4.4.1), as is a method
	// without a challenge, which §4.3 requires, and a challenge of another
	// form than §4.2 gives.
	challenge, method := params.Get("code_challenge"), params.Get("code_challenge_method")
	switch {
	case challenge == "" && method != "":
		return req, errInvalidRequest, "The parameter code_challenge_method requires code_challenge."
	case challenge == "" && client.Public():
		return req, errInvalidRequest, "A public client must send code_challenge: PKCE is required."
	case challenge == "":
		// A confidential Client that does not use PKCE.
	case method != "S256":
		return req, errInvalidRequest, "Only the code_challenge_method S256 is supported."
	case !validPKCEValue(challenge):
		return req, errInvalidRequest, "The code_challenge must be 43 to 128 unreserved characters."
	}

	var scopes []string
	for s := range strings.FieldsSeq(params.Get("scope")) {
		if _, ok := supportedScope(s); ok && !slices.Contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}
	if !slices.Contains(scopes, "openid") {
		return req, errInvalidScope, "The scope must include openid."
	}

	// A value pulsar does not know is ignored, as OpenID Connect Core 1.0
	// §3.1.2.1 allows, except that none admits no other.
	prompt := strings.Fields(params.Get("prompt"))
	if slices.Contains(prompt, "none") && slices.ContainsFunc(prompt, func(v string) bool { return v != "none" }) {
		return req, errInvalidRequest, "The prompt value none cannot be combined with another."
	}

	maxAge := int64(-1)
	if v := params.Get("max_age"); v != "" {
		if strings.Trim(v, "0123456789") != "" {
			return req, errInvalidRequest, "The parameter max_age must be a number of seconds."
		}
		n, err := strconv.ParseInt(v, 10, 64)
		// A number of seconds too large to hold is a limit no
		// authentication can exceed, and is no limit.
		if err == nil {
			maxAge = n
		}
	}

	var hintSubject string
	if v := params.Get("id_token_hint"); v != "" {
		var ok bool
		if hintSubject, ok = idTokenSubject(v, issuer); !ok {
			return req, errInvalidRequest, "The id_token_hint is not a JWT that names this OP as its issuer and an End-User as its subject."
		}
	}

	return authorizationRequest{
		client:      client,
		redirectURI: redirectURI,
		scopes:      scopes,
		nonce:       params.Get("nonce"),
		challenge:   challenge,
		prompt:      prompt,
		maxAge:      maxAge,
		hintSubject: hintSubject,
	}, "", ""
}

// idTokenSubject returns the sub of idToken, a JWT that names issuer as
// its iss and that pulsar would sign, with RS256.
//
// The signature is not verified, nor is exp checked: a hint may have
// expired (OpenID Connect Core 1.0 §3.1.2.1 only requires that it was
// issued), and the hint only narrows the End-Users a positive response may
// be about. Whatever End-User a forged hint names, the response is about
// the End-User signed in, as it would be without the hint, or an error.
func idTokenSubject(idToken, issuer string) (string, bool) {
	jws, err := jose.ParseSignedCompact(idToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return "", false
	}
	var claims struct {
		Issuer  string `json:"iss"`
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &claims); err != nil {
		return "", false
	}
	if claims.Issuer != issuer || claims.Subject == "" {
		return "", false
	}
	return claims.Subject, true
}

// needsLogin reports whether the request asks the End-User, who
// authenticated at authTime, to authenticate again now (OpenID Connect
// Core 1.0 §3.1.2.1).
//
// prompt=login, prompt=select_account (a Login Session holds one
// End-User, and the login page is where they choose another) and
// max_age=0, which §3.1.2.1 equates with prompt=login, ask whatever the
// time, unless fresh: the End-User signed in on the login page for this
// request, which seconds are too coarse to tell from a login just before
// it.
//
// A max_age the time since authTime exceeds asks too, unless answered:
// after that login for this request, the End-User also decided on the
// consent page for it, so the request was re-authenticated, as max_age
// asks, and is now complete. Otherwise an End-User slower on the consent
// page than max_age would be sent to log in, which clears the decision,
// and around again. A consent page left unanswered is no answer, and the
// same request sent again later is measured from the login.
func (req authorizationRequest) needsLogin(authTime, now time.Time, fresh, answered bool) bool {
	if req.maxAge > 0 && !answered && now.Unix()-authTime.Unix() > req.maxAge {
		return true
	}
	return !fresh && (req.prompts("login") || req.prompts("select_account") || req.maxAge == 0)
}

// prompts reports whether the request's prompt parameter holds value.
func (req authorizationRequest) prompts(value string) bool {
	return slices.Contains(req.prompt, value)
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
	// The code challenge is stored with the code, so that the token
	// endpoint can verify the code_verifier against it (RFC 7636 §4.4).
	err := p.queries.InsertAuthorizationCode(ctx, queries.InsertAuthorizationCodeParams{
		CodeHash:      hash,
		ClientID:      req.client.ID,
		RedirectUri:   req.redirectURI,
		Subject:       auth.EndUser.Subject,
		Scopes:        req.scopes,
		Nonce:         req.nonce,
		CodeChallenge: req.challenge,
		AuthTime:      auth.Time,
		Expiry:        now.Add(codeLifetime),
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
