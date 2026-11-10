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

// offlineAccessScope asks for a refresh token (OpenID Connect Core 1.0
// §11). It is granted only with prompt=consent, and never from a Consent
// (see login.OfflineAccess). Discovery lists it after supportedScopes.
var offlineAccessScope = login.Scope{
	Value:       login.OfflineAccess,
	Description: "access while you are away, so that the client can keep acting for you when you are not signed in",
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
	if value == login.OfflineAccess {
		return offlineAccessScope, true
	}
	i := slices.IndexFunc(supportedScopes, func(s login.Scope) bool { return s.Value == value })
	if i < 0 {
		return login.Scope{}, false
	}
	return supportedScopes[i], true
}

// authorizationParams are the parameters of an authorization request that
// pulsar reads, besides resource, which RFC 8707 §2 lets a Client repeat,
// and which is checked apart, with its own error code (parseResource).
// Every other parameter is ignored (RFC 6749 §3.1).
var authorizationParams = []string{
	"client_id", "redirect_uri", "response_type", "response_mode",
	"scope", "state", "nonce", "request", "request_uri",
	"prompt", "max_age", "login_hint", "id_token_hint",
	"code_challenge", "code_challenge_method", "claims",
}

// The Response Modes pulsar supports: query, the default of the
// response_type code (RFC 6749 §4.1.2), and form_post (OAuth 2.0 Form Post
// Response Mode §2).
// responseModes lists them, as discovery does, and the authorization
// endpoint accepts no other.
const (
	responseModeQuery    = "query"
	responseModeFormPost = "form_post"
)

var responseModes = []string{responseModeQuery, responseModeFormPost}

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
	errTemporarilyUnavailable  = "temporarily_unavailable"
	errRequestNotSupported     = "request_not_supported"
	errRequestURINotSupported  = "request_uri_not_supported"
	// RFC 8707 §2, at the authorization endpoint (§2.1) and the token
	// endpoint (§2.2).
	errInvalidTarget = "invalid_target"
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
	// A machine Client acts for itself, never for an End-User. It has no
	// redirect URI to send unauthorized_client to (RFC 6749 §4.1.2.1), so
	// the End-User is told here.
	if !client.AllowsGrant(registry.AuthorizationCode) {
		p.errorPage(w, "The authorization request names a client that is not registered for the authorization code flow.")
		return
	}
	// The URI redirected to, and recorded with the code, is the request's:
	// one the Client registered, or, for a public Client, a loopback IP
	// redirect URI it registered with the port the request names.
	v := params["redirect_uri"]
	if len(v) != 1 || !client.AllowsRedirectURI(v[0]) {
		p.errorPage(w, "The authorization request's redirect_uri is not one the client registered.")
		return
	}
	redirectURI := v[0]

	// The Response Mode is read before any other parameter, so that every
	// error from here on goes by the one requested (OpenID Connect Core 1.0
	// §3.1.2.6). A response_mode repeated, of a value pulsar does not
	// support, or of form_post for a redirect URI a browser cannot POST to,
	// is refused below, by query.
	resp := authorizationResponse{
		redirectURI: redirectURI,
		issuer:      p.issuer.String(),
		formPost:    slices.Equal(params["response_mode"], []string{responseModeFormPost}) && postable(redirectURI),
	}
	if state := params["state"]; len(state) > 0 {
		resp.state = state[0]
	}
	req, errCode, errDesc := parseAuthorizationRequest(p.registry, client, redirectURI, p.issuer.String(), params)
	if errCode != "" {
		resp.sendError(w, r, errCode, errDesc)
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
		resp.sendError(w, r, errServerError, "")
		return
	}
	// respond saves the Login Session, which must precede any part of the
	// response, and then answers with answer.
	respond := func(answer func()) { //nolint:contextcheck // Save uses the context of r, which Interaction keeps.
		if err := inter.Save(w); err != nil {
			p.logger.ErrorContext(ctx, "authorization endpoint", "error", err)
			resp.sendError(w, r, errServerError, "")
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
		respond(func() { resp.sendError(w, r, errServerError, "") })
	}
	// ask shows the End-User a page, with show; but with prompt=none, no
	// page is shown, and what the page would ask for is answered with the
	// error code errCode instead (OpenID Connect Core 1.0 §3.1.2.1,
	// §3.1.2.6). pulsar asks for nothing but a login and a Consent, so it
	// never needs interaction_required.
	ask := func(errCode, desc string, show func()) {
		if req.prompts("none") {
			respond(func() { resp.sendError(w, r, errCode, desc) })
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
	// than one the request names, by id_token_hint or by a sub Claim
	// requested with a value, is sent to log in once; if that login is not
	// a named End-User's either, the request fails (OpenID Connect Core 1.0
	// §3.1.2.1, §3.1.2.2).
	subject := auth.EndUser.Subject
	otherEndUser := req.subjects != nil && !slices.Contains(req.subjects, subject)
	fresh := inter.SignedInForRequest()
	decided := inter.Decision() != login.Undecided
	if (otherEndUser && !fresh) || req.needsLogin(auth.Time, time.Now(), fresh, fresh && decided) {
		ask(errLoginRequired, "The request requires a new login.", toLogin)
		return
	}
	if otherEndUser {
		inter.Finish()
		respond(func() {
			resp.sendError(w, r, errLoginRequired, "The End-User signed in is not one the request names.")
		})
		return
	}

	// An authorization decision, before anything is released (OpenID
	// Connect Core 1.0 §3.1.2.4): the one the End-User just made on the
	// consent page for this request, or else their Consent. It covers the
	// scopes requested, and those that request the claims the claims
	// parameter asks for, so that no claim is released without the
	// End-User's Consent to its scope.
	consentScopes := req.consentScopes()
	switch inter.Decision() {
	case login.Denied:
		inter.Finish()
		respond(func() { resp.sendError(w, r, errAccessDenied, "The End-User denied the request.") })
		return
	case login.Allowed:
		// A public Client's Consent is never consulted (see below), so it
		// is not kept.
		if !req.client.Public() {
			if err := p.consents.Allow(ctx, subject, req.client.ID, consentScopes, req.resourceIdentifier()); err != nil {
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
			covered, err = p.consents.Covers(ctx, subject, req.client.ID, consentScopes, req.resourceIdentifier())
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
				// consentScopes holds supported scopes, and the Resource
				// Server's, only.
				for _, s := range consentScopes {
					if scope, ok := supportedScope(s); ok {
						page.Scopes = append(page.Scopes, scope)
					}
				}
				if req.resource != nil {
					page.ResourceServer = req.resource.Identifier
					for _, sc := range req.resource.Scopes {
						if slices.Contains(consentScopes, sc.Value) {
							page.ResourceScopes = append(page.ResourceScopes, login.Scope{Value: sc.Value, Description: sc.Description})
						}
					}
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
	respond(func() { resp.send(w, r, url.Values{"code": {code}}) })
}

// authorizationRequest is an authorization request whose Client and
// redirect URI are valid and whose other parameters pulsar accepts.
type authorizationRequest struct {
	client      *registry.Client
	redirectURI string
	// resource is the Resource Server the resource parameter names, or nil
	// if the request sent none.
	resource  *registry.ResourceServer
	scopes    []string // the scope values granted
	nonce     string
	challenge string   // the S256 code_challenge (RFC 7636 §4.3), or "" if it was not sent
	prompt    []string // the values of the prompt parameter (OpenID Connect Core 1.0 §3.1.2.1)
	maxAge    int64    // the max_age parameter, in seconds, or -1 if it sets no limit
	// subjects are the Subjects of the End-Users a positive response may be
	// about, as id_token_hint and a sub Claim requested in the ID token
	// with a value name them; nil if the request names none.
	subjects []string
	claims   claimsRequest // the claims parameter (OpenID Connect Core 1.0 §5.5)
}

// resourceIdentifier returns the identifier of the Resource Server the
// request names, as a code and a Consent record it, or "" for none.
func (req authorizationRequest) resourceIdentifier() string {
	if req.resource == nil {
		return ""
	}
	return req.resource.Identifier
}

// consentScopes returns the scopes the End-User's Consent must cover for
// the request: those it requests, and those that request the claims its
// claims parameter asks for (OpenID Connect Core 1.0 §5.4).
func (req authorizationRequest) consentScopes() []string {
	scopes := slices.Clone(req.scopes)
	for _, s := range req.claims.scopes() {
		if !slices.Contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}
	return scopes
}

// parseAuthorizationRequest checks the parameters of an authorization
// request for client, with redirectURI, one it allows (see
// registry.Client.AllowsRedirectURI), to the OP at
// issuer, whose registry is reg, and returns the request, or the error
// code and description to redirect with.
func parseAuthorizationRequest(reg *registry.Registry, client *registry.Client, redirectURI, issuer string, params url.Values) (req authorizationRequest, errCode, errDesc string) {
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
	switch mode := params.Get("response_mode"); {
	case mode != "" && !slices.Contains(responseModes, mode):
		return req, errInvalidRequest, "Only the response_modes " + strings.Join(responseModes, " and ") + " are supported."
	case mode == responseModeFormPost && !postable(redirectURI):
		return req, errInvalidRequest, "The response_mode form_post requires a redirect_uri whose scheme is http or https."
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

	resource, ok := parseResource(reg, client, params["resource"])
	if !ok {
		return req, errInvalidTarget, "The resource must be one Resource Server registered for this client, named by its identifier."
	}

	// A scope pulsar does not support is ignored (RFC 6749 §3.3), as is
	// one of a Resource Server other than the one resource names, or of
	// any Resource Server without resource: that Resource Server is not
	// the default resource, pulsar's UserInfo, so the request stays one for
	// UserInfo, as it is without such a scope.
	var scopes []string
	for s := range strings.FieldsSeq(params.Get("scope")) {
		if _, ok := supportedScope(s); !ok && (resource == nil || !resource.HasScope(s)) {
			continue
		}
		if !slices.Contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}
	if !slices.Contains(scopes, "openid") {
		return req, errInvalidScope, "The scope must include openid."
	}
	// An access token for a Resource Server allows at least one of its
	// scopes; one that allowed none would be an invalid combination of
	// resource and scope (RFC 8707 §2).
	if resource != nil && !slices.ContainsFunc(scopes, resource.HasScope) {
		return req, errInvalidTarget, "The scope must include a scope of the Resource Server the resource names."
	}

	// A value pulsar does not know is ignored, as OpenID Connect Core 1.0
	// §3.1.2.1 allows, except that none admits no other.
	prompt := strings.Fields(params.Get("prompt"))
	if slices.Contains(prompt, "none") && slices.ContainsFunc(prompt, func(v string) bool { return v != "none" }) {
		return req, errInvalidRequest, "The prompt value none cannot be combined with another."
	}
	// Offline access is asked of the End-User on the consent page, which
	// prompt=consent always shows. Without it, offline_access is ignored
	// (OpenID Connect Core 1.0 §11).
	if !slices.Contains(prompt, "consent") {
		scopes = slices.DeleteFunc(scopes, func(s string) bool { return s == login.OfflineAccess })
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

	var subjects []string
	if v := params.Get("id_token_hint"); v != "" {
		hintSubject, ok := idTokenSubject(v, issuer)
		if !ok {
			return req, errInvalidRequest, "The id_token_hint is not a JWT that names this OP as its issuer and an End-User as its subject."
		}
		subjects = []string{hintSubject}
	}

	var claims claimsRequest
	if v := params.Get("claims"); v != "" {
		var claimed []string
		var err error
		if claims, claimed, err = parseClaimsParameter(v); err != nil {
			return req, errInvalidRequest, "The parameter claims is not a JSON object of the form OpenID Connect Core 1.0 §5.5 gives."
		}
		// A request may name End-Users by both id_token_hint and the sub
		// Claim; a response may be about one that both name.
		if claimed != nil && subjects != nil {
			claimed = slices.DeleteFunc(claimed, func(s string) bool { return !slices.Contains(subjects, s) })
		}
		if claimed != nil {
			if len(claimed) == 0 {
				return req, errInvalidRequest, "The request names no End-User that id_token_hint and the sub Claim both allow."
			}
			subjects = claimed
		}
	}

	// The access token for a Resource Server is refused at UserInfo, so the
	// claims requested from UserInfo could never be released. They are
	// ignored, as a claim pulsar cannot release is (OpenID Connect Core 1.0
	// §5.5.1, REQ-CORE-45), and the End-User is not asked for their scopes.
	if resource != nil {
		claims.UserInfo = nil
	}

	return authorizationRequest{
		client:      client,
		redirectURI: redirectURI,
		resource:    resource,
		scopes:      scopes,
		nonce:       params.Get("nonce"),
		challenge:   challenge,
		prompt:      prompt,
		maxAge:      maxAge,
		subjects:    subjects,
		claims:      claims,
	}, "", ""
}

// parseResource returns the Resource Server that values, the values of an
// authorization request's resource parameter, name, or nil if they are
// none. They must be one value, the identifier of a Resource Server that
// client may request, compared as a string, exactly as it is registered.
// A value that is not an absolute URI without a fragment (RFC 8707 §2)
// matches no identifier, since every identifier is one. More than one
// value, even the same one twice, is refused rather than turned into an
// access token for several audiences, as RFC 8707 §3 encourages.
func parseResource(reg *registry.Registry, client *registry.Client, values []string) (*registry.ResourceServer, bool) {
	switch len(values) {
	case 0:
		return nil, true
	case 1:
		return reg.ResourceServer(client, values[0])
	default:
		return nil, false
	}
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
	claims, err := req.claims.encode()
	if err != nil {
		return "", err
	}
	code, hash := newCode()
	// The code challenge, the claims requested and the Resource Server are
	// stored with the code, so that the token endpoint can verify the
	// code_verifier against the one (RFC 7636 §4.4), release the other, and
	// issue access tokens for the third (RFC 8707 §2.1).
	err = p.queries.InsertAuthorizationCode(ctx, queries.InsertAuthorizationCodeParams{
		CodeHash:      hash,
		ClientID:      req.client.ID,
		RedirectUri:   req.redirectURI,
		Subject:       auth.EndUser.Subject,
		Scopes:        req.scopes,
		Nonce:         req.nonce,
		CodeChallenge: req.challenge,
		Claims:        claims,
		Resource:      req.resourceIdentifier(),
		AuthTime:      auth.Time,
		Expiry:        now.Add(codeLifetime),
	})
	if err != nil {
		return "", err
	}
	return code, nil
}

// authorizationResponse sends the authorization response, success or
// error, to a Client's redirect URI, by the Response Mode the request
// asked for.
type authorizationResponse struct {
	redirectURI string
	state       string
	issuer      string
	formPost    bool // whether the Response Mode is form_post rather than query
}

// send sends params, with state and iss (RFC 6749 §4.1.2, RFC 9207 §2)
// added, to the redirect URI. With form_post, the browser posts them there
// from a form-post page (see writeFormPost). Otherwise it is redirected
// there with them in the query, appended to any query the redirect URI
// has, which is kept as registered (RFC 6749 §3.1.2).
func (a authorizationResponse) send(w http.ResponseWriter, r *http.Request, params url.Values) {
	if a.state != "" {
		params.Set("state", a.state)
	}
	params.Set("iss", a.issuer)
	if a.formPost {
		writeFormPost(w, a.redirectURI, params)
		return
	}
	// The response carries a code, which no cache may keep. 303, as RFC
	// 9700 §4.12 advises, so that a request sent by POST is not sent on.
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, withQuery(a.redirectURI, params), http.StatusSeeOther)
}

// withQuery returns uri with params added to any query it has, which is
// kept as registered (RFC 6749 §3.1.2).
func withQuery(uri string, params url.Values) string {
	sep := "?"
	switch {
	case strings.HasSuffix(uri, "?") || strings.HasSuffix(uri, "&"):
		sep = ""
	case strings.Contains(uri, "?"):
		sep = "&"
	}
	return uri + sep + params.Encode()
}

// sendError sends an error response (RFC 6749 §4.1.2.1) to the redirect
// URI. desc, if any, is fixed text that never repeats the request.
func (a authorizationResponse) sendError(w http.ResponseWriter, r *http.Request, code, desc string) {
	params := url.Values{"error": {code}}
	if desc != "" {
		params.Set("error_description", desc)
	}
	a.send(w, r, params)
}

// errorPage tells the End-User that the authorization or logout request is
// invalid, without redirecting. msg is fixed text that never repeats the
// request.
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
