// Package webapp is an example web app: a confidential Client that runs
// on the server, the backend-for-frontend RFC 10017 §6.1 recommends. It
// signs the End-User in with pulsar, keeps their tokens on the server, and
// gives the browser only cookies of its own. With the access token it gets
// for the API example, it lists and adds the End-User's notes there,
// refreshing the token when it expires. Its logout revokes its refresh
// token and sends the End-User to pulsar to sign out there too.
//
//	GET  /            the home page: who is signed in, or a link to sign in
//	GET  /login       starts a sign-in, with a redirect to pulsar
//	GET  /callback    the redirect URI, where pulsar sends the browser back
//	GET  /notes       the End-User's notes, from the API
//	POST /notes       adds a note, from the form field text, through the API
//	POST /logout      revokes the refresh token, and redirects to pulsar's logout
//	GET  /signed-out  the post-logout redirect URI, where pulsar sends the browser back
package webapp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// The scopes of the API's Resource Server, as pulsar's registry lists
// them, that the web app asks for.
const (
	scopeRead  = "notes:read"
	scopeWrite = "notes:write"
)

// The paths of the redirect URI and the post-logout redirect URI, under
// Config.URL, as the web app registered them.
const (
	callbackPath  = "/callback"
	signedOutPath = "/signed-out"
)

// The web app's cookies. Each is Secure, HttpOnly and has Path=/ and no
// Domain, as the __Host-Http- prefix requires a browser to check (RFC
// 10017 §6.1.3.2).
const (
	// sessionCookie names the End-User's session, once they are signed in.
	// It is SameSite=Strict, so that a browser sends it on no request
	// another site starts (RFC 10017 §6.1.3.2, §6.1.3.3.1).
	sessionCookie = "__Host-Http-webapp-session"
	// flowCookie names a sign-in or a logout in progress. The browser comes
	// back to the web app from pulsar, another site, by a navigation that
	// a SameSite=Strict cookie would not be sent on, so it is
	// SameSite=Lax, which is sent on a navigation by GET. It lasts as long
	// as a flow.
	flowCookie = "__Host-Http-webapp-flow"
)

// flowLifetime bounds how long the End-User has to sign in, or to sign
// out at pulsar, before the web app forgets the flow.
const flowLifetime = 10 * time.Minute

// expiryMargin is how long before its expiry an access token is refreshed,
// so that it does not expire on its way to the API.
const expiryMargin = 10 * time.Second

// Config is the web app's registration with pulsar, and where it finds the
// API.
type Config struct {
	// Issuer is pulsar's Issuer Identifier.
	Issuer string
	// ClientID and ClientSecret are the web app's credentials, registered
	// for client_secret_basic.
	ClientID     string
	ClientSecret string
	// URL is the web app's URL, as the browser reaches it, with no path:
	// its redirect URI is URL/callback, and its post-logout redirect URI
	// URL/signed-out, as registered.
	URL string
	// APIURL is the API's URL, and APIIdentifier its identifier, sent as
	// the resource parameter for an access token for the API (RFC 8707).
	APIURL        string
	APIIdentifier string
	// HTTPClient makes the web app's requests to pulsar and to the API;
	// http.DefaultClient, if nil.
	HTTPClient *http.Client
	// Now returns the time against which tokens' expiry is checked; the
	// clock, if nil. A test sets it to make the access token expire.
	Now func() time.Time
}

// Server is the web app. It is an http.Handler.
type Server struct {
	cfg                Config
	oauth              oauth2.Config
	verifier           *oidc.IDTokenVerifier
	issParameter       bool
	revocationEndpoint string
	endSessionEndpoint *url.URL
	handler            http.Handler

	mu       sync.Mutex
	sessions map[string]*session // by the value of sessionCookie
	flows    map[string]*flow    // by the value of flowCookie
}

// session is a signed-in End-User's session, with their tokens.
type session struct {
	subject string
	// idToken is the ID token of the sign-in, sent as id_token_hint at
	// logout.
	idToken string

	// mu is held while the tokens are read, refreshed or revoked, so that
	// one refresh runs at a time: pulsar rotates the refresh token, and
	// takes a used one presented again as stolen, revoking them all.
	mu     sync.Mutex
	token  *oauth2.Token
	expiry time.Time // of token's access token, by Config.Now
}

// flow is a sign-in or a logout in progress.
type flow struct {
	started time.Time
	// For a sign-in: its state, nonce and PKCE code_verifier.
	state, nonce, verifier string
	// For a logout: the state sent to pulsar's logout endpoint.
	logoutState string
}

// New discovers pulsar's endpoints from its discovery document at
// cfg.Issuer, and returns the web app. ctx is used for discovery and, for
// as long as the web app serves, for fetching pulsar's JWK Set.
func New(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("webapp: the client_id and client_secret are required")
	}
	if cfg.URL == "" || cfg.APIURL == "" || cfg.APIIdentifier == "" {
		return nil, errors.New("webapp: the web app's URL, and the API's URL and identifier, are required")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	cfg.URL = strings.TrimSuffix(cfg.URL, "/")
	ctx = oidc.ClientContext(ctx, cfg.HTTPClient)
	// NewProvider refuses a discovery document whose issuer is not
	// cfg.Issuer exactly (OpenID Connect Discovery 1.0 §4.3).
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("webapp: discover %s: %w", cfg.Issuer, err)
	}
	var meta struct {
		IssParameter       bool   `json:"authorization_response_iss_parameter_supported"`
		RevocationEndpoint string `json:"revocation_endpoint"`
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&meta); err != nil {
		return nil, fmt.Errorf("webapp: the discovery document of %s: %w", cfg.Issuer, err)
	}
	if meta.RevocationEndpoint == "" || meta.EndSessionEndpoint == "" {
		return nil, fmt.Errorf("webapp: the discovery document of %s has no revocation_endpoint or end_session_endpoint", cfg.Issuer)
	}
	endSession, err := url.Parse(meta.EndSessionEndpoint)
	if err != nil {
		return nil, fmt.Errorf("webapp: end_session_endpoint: %w", err)
	}

	endpoint := provider.Endpoint()
	// A confidential Client authenticates by HTTP Basic, the method every
	// authorization server must support (RFC 6749 §2.3.1), and the one
	// registered for it.
	endpoint.AuthStyle = oauth2.AuthStyleInHeader
	s := &Server{
		cfg: cfg,
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     endpoint,
			RedirectURL:  cfg.URL + callbackPath,
			// offline_access asks for a refresh token (OpenID Connect Core 1.0
			// §11), with the API's scopes for an access token for it.
			Scopes: []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess, scopeRead, scopeWrite},
		},
		verifier:           provider.Verifier(&oidc.Config{ClientID: cfg.ClientID, Now: cfg.Now}),
		issParameter:       meta.IssParameter,
		revocationEndpoint: meta.RevocationEndpoint,
		endSessionEndpoint: endSession,
		sessions:           make(map[string]*session),
		flows:              make(map[string]*flow),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("GET "+callbackPath, s.callback)
	mux.HandleFunc("GET /notes", s.listNotes)
	mux.HandleFunc("POST /notes", s.addNote)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET "+signedOutPath, s.signedOut)
	// The CSRF defense RFC 10017 §6.1.3.3 requires: a request that is not
	// GET or HEAD is refused if the browser says another origin sent it.
	// SameSite=Strict alone would let through one from another origin of
	// the same site (§6.1.3.3.1).
	s.handler = http.NewCrossOriginProtection().Handler(mux)
	return s, nil
}

// ServeHTTP serves the web app's routes.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// No page the web app serves is to be cached, or to name it in the
	// Referer of a request to another site.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	s.handler.ServeHTTP(w, r)
}

// outbound returns ctx with the HTTP client of the web app's requests, as
// x/oauth2 and go-oidc read it.
func (s *Server) outbound(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, s.cfg.HTTPClient)
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	// The End-User's sub, from the ID token. A name would come from
	// UserInfo, which accepts only access tokens for pulsar, not the one
	// for the API the web app holds.
	var subject string
	if sess, ok := s.session(r); ok {
		subject = sess.subject
	}
	render(w, http.StatusOK, homePage, subject)
}

// login starts a sign-in: it remembers a new state, nonce and PKCE
// code_verifier for this browser, and sends it to pulsar's authorization
// endpoint.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	// PKCE, which RFC 9700 §2.1.1 recommends to a confidential Client too,
	// against the injection of a code; state, against cross-site request
	// forgery (RFC 6749 §10.12); and nonce, binding the ID token to this
	// request (OpenID Connect Core 1.0 §3.1.2.1).
	f := &flow{state: rand.Text(), nonce: rand.Text(), verifier: oauth2.GenerateVerifier()}
	s.startFlow(w, f)
	authURL := s.oauth.AuthCodeURL(f.state,
		oauth2.S256ChallengeOption(f.verifier),
		oidc.Nonce(f.nonce),
		// pulsar issues a refresh token for offline_access only with
		// prompt=consent (OpenID Connect Core 1.0 §11).
		oauth2.SetAuthURLParam("prompt", "consent"),
		oauth2.SetAuthURLParam("resource", s.cfg.APIIdentifier),
	)
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// callback is the redirect URI. It checks that the response answers the
// sign-in this browser started, redeems the code, verifies the ID token,
// and starts the End-User's session.
func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	// The response must carry the state of the sign-in this browser
	// started, so that another site cannot make the web app redeem a code
	// it did not ask for (RFC 6749 §10.12). One that does not is refused,
	// and leaves the sign-in to finish.
	f := s.endFlow(w, r, func(f *flow) bool { return f.state != "" && q.Get("state") == f.state })
	if f == nil {
		message(w, http.StatusBadRequest, "This is not the response to a sign-in this browser started.")
		return
	}
	switch {
	// The response comes from pulsar, and no other authorization server: it
	// names pulsar in iss, which pulsar's discovery document says it
	// always sends (RFC 9207 §2.4).
	case (s.issParameter || q.Has("iss")) && q.Get("iss") != s.cfg.Issuer:
		message(w, http.StatusBadRequest, "The response does not come from pulsar.")
		return
	case q.Has("error"):
		message(w, http.StatusForbidden, "Sign-in refused: "+q.Get("error"))
		return
	}

	ctx := s.outbound(r.Context())
	// The code is redeemed with the code_verifier, the client's
	// credentials, and the same resource, as RFC 8707 §2.2 allows.
	token, err := s.oauth.Exchange(ctx, q.Get("code"),
		oauth2.VerifierOption(f.verifier),
		oauth2.SetAuthURLParam("resource", s.cfg.APIIdentifier),
	)
	if err != nil {
		message(w, http.StatusBadGateway, "The code could not be redeemed.")
		return
	}
	// The ID token is verified as OpenID Connect Core 1.0 §3.1.3.7 says:
	// its signature against pulsar's JWK Set, iss, aud, exp, and nonce.
	rawIDToken, _ := token.Extra("id_token").(string)
	idToken, err := s.verifier.Verify(ctx, rawIDToken)
	if err != nil || idToken.Nonce != f.nonce {
		message(w, http.StatusBadGateway, "The ID token is not valid.")
		return
	}

	id := rand.Text()
	s.mu.Lock()
	s.sessions[id] = &session{subject: idToken.Subject, idToken: rawIDToken, token: token, expiry: s.expiry(token)}
	s.mu.Unlock()
	setCookie(w, sessionCookie, id, 0, http.SameSiteStrictMode)
	// The browser came here from pulsar, another site, so it would not send
	// the SameSite=Strict session cookie on a redirect that went on from
	// here; a page that refreshes to the home page is a navigation of the
	// web app's own, on which it does.
	render(w, http.StatusOK, signedInPage, nil)
}

// listNotes shows the End-User's notes, from the API.
func (s *Server) listNotes(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.session(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	var body struct {
		Notes []string `json:"notes"`
	}
	if !s.callAPI(w, r, sess, http.MethodGet, nil, http.StatusOK, &body) {
		return
	}
	render(w, http.StatusOK, notesPage, body.Notes)
}

// addNote adds a note through the API, and shows the notes.
func (s *Server) addNote(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.session(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	text := r.PostFormValue("text")
	if strings.TrimSpace(text) == "" {
		message(w, http.StatusBadRequest, "A note needs text.")
		return
	}
	b, err := json.Marshal(struct {
		Text string `json:"text"`
	}{text})
	if err != nil {
		message(w, http.StatusInternalServerError, "The note could not be sent.")
		return
	}
	if !s.callAPI(w, r, sess, http.MethodPost, b, http.StatusCreated, nil) {
		return
	}
	// 303, so that reloading the page does not add the note again.
	http.Redirect(w, r, "/notes", http.StatusSeeOther)
}

// callAPI calls the API's /notes with the session's access token, and
// decodes the response's body into out, unless it is nil. If the call
// fails, it answers w and reports false.
func (s *Server) callAPI(w http.ResponseWriter, r *http.Request, sess *session, method string, body []byte, want int, out any) bool {
	ctx := r.Context()
	accessToken, err := s.accessToken(s.outbound(ctx), sess)
	if errors.Is(err, errRefreshRefused) {
		s.endSession(w, r)
		message(w, http.StatusUnauthorized, "Your session has ended; sign in again.")
		return false
	}
	if err != nil {
		message(w, http.StatusBadGateway, "pulsar could not be reached to refresh the access token.")
		return false
	}
	req, err := http.NewRequestWithContext(ctx, method, s.cfg.APIURL+"/notes", bytes.NewReader(body))
	if err != nil {
		message(w, http.StatusInternalServerError, "The API could not be called.")
		return false
	}
	// The access token goes in the Authorization header (RFC 6750 §2.1).
	req.Header.Set("Authorization", "Bearer "+accessToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		message(w, http.StatusBadGateway, "The API could not be reached.")
		return false
	}
	defer resp.Body.Close() //nolint:errcheck // Closing a response body reports nothing to act on.
	if resp.StatusCode != want {
		message(w, http.StatusBadGateway, fmt.Sprintf("The API answered %d.", resp.StatusCode))
		return false
	}
	if out != nil && json.NewDecoder(resp.Body).Decode(out) != nil {
		message(w, http.StatusBadGateway, "The API's answer could not be read.")
		return false
	}
	return true
}

// errRefreshRefused is the error of accessToken when pulsar refuses the
// session's refresh token: the session can get no more access tokens.
var errRefreshRefused = errors.New("webapp: the refresh token was refused")

// accessToken returns the session's access token, refreshed first if it
// has expired, or is about to, by Config.Now. ctx carries the HTTP client.
func (s *Server) accessToken(ctx context.Context, sess *session) (string, error) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if s.cfg.Now().Before(sess.expiry.Add(-expiryMargin)) {
		return sess.token.AccessToken, nil
	}
	// A token with no access token makes the token source refresh it, with
	// the client's credentials (RFC 6749 §6). pulsar keeps the resource of
	// the sign-in for every refresh, so none is sent (RFC 8707 §2.2).
	token, err := s.oauth.TokenSource(ctx, &oauth2.Token{RefreshToken: sess.token.RefreshToken}).Token()
	if re, ok := errors.AsType[*oauth2.RetrieveError](err); ok && re.ErrorCode == "invalid_grant" {
		return "", fmt.Errorf("%w: %w", errRefreshRefused, err)
	}
	if err != nil {
		return "", err
	}
	// The refresh token pulsar returned replaces the one redeemed, which
	// pulsar will not accept again (RFC 9700 §4.14.2).
	sess.token, sess.expiry = token, s.expiry(token)
	return token.AccessToken, nil
}

// expiry returns when token's access token expires, by Config.Now, from
// its expires_in: the Client does not read the access token itself (RFC
// 6749 §1.4).
func (s *Server) expiry(token *oauth2.Token) time.Time {
	return s.cfg.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
}

// logout revokes the session's refresh token, ends the session, and sends
// the browser to pulsar's logout endpoint, to sign out there too.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.session(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// Revoking the refresh token revokes its whole grant at pulsar, so no
	// one can use it once the session ends (RFC 7009 §2.1, RFC 10017
	// §6.1.2.3). If pulsar cannot be reached, the session is kept, so that
	// the End-User can try again.
	sess.mu.Lock()
	err := s.revoke(s.outbound(r.Context()), sess.token.RefreshToken)
	sess.mu.Unlock()
	if err != nil {
		message(w, http.StatusBadGateway, "The refresh token could not be revoked; try again.")
		return
	}
	s.endSession(w, r)

	// RP-Initiated Logout 1.0 §2: the ID token as id_token_hint, which
	// tells pulsar which Client and End-User this is; the post-logout
	// redirect URI the web app registered; and a state the web app checks
	// when the browser comes back.
	f := &flow{logoutState: rand.Text()}
	s.startFlow(w, f)
	u := *s.endSessionEndpoint
	q := u.Query()
	q.Set("id_token_hint", sess.idToken)
	q.Set("post_logout_redirect_uri", s.cfg.URL+signedOutPath)
	q.Set("state", f.logoutState)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

// revoke revokes refreshToken at pulsar's revocation endpoint, by HTTP
// Basic, as at the token endpoint (RFC 7009 §2.1). ctx carries the HTTP
// client.
func (s *Server) revoke(ctx context.Context, refreshToken string) error {
	form := url.Values{"token": {refreshToken}, "token_type_hint": {"refresh_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.revocationEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// The client_id and secret are form-encoded before they are joined
	// (RFC 6749 §2.3.1).
	req.SetBasicAuth(url.QueryEscape(s.cfg.ClientID), url.QueryEscape(s.cfg.ClientSecret))
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck // Closing a response body reports nothing to act on.
	_, _ = io.Copy(io.Discard, resp.Body)
	// 200 means revoked, or already invalid; both leave nothing to revoke
	// (RFC 7009 §2.2).
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the revocation endpoint answered %d", resp.StatusCode)
	}
	return nil
}

// signedOut is the post-logout redirect URI. It checks that the browser
// comes back from the logout this browser started, by its state.
func (s *Server) signedOut(w http.ResponseWriter, r *http.Request) {
	// pulsar passes the state back unchanged (RP-Initiated Logout 1.0 §2).
	// A return with another is refused, and leaves the logout to finish.
	state := r.URL.Query().Get("state")
	if f := s.endFlow(w, r, func(f *flow) bool { return f.logoutState != "" && state == f.logoutState }); f == nil {
		message(w, http.StatusBadRequest, "This is not the return from a logout this browser started.")
		return
	}
	render(w, http.StatusOK, signedOutPage, nil)
}

// session returns the session r's cookie names, if there is one.
func (s *Server) session(r *http.Request) (*session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[c.Value]
	return sess, ok
}

// endSession forgets the session r's cookie names, and removes the cookie.
func (s *Server) endSession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	setCookie(w, sessionCookie, "", -1, http.SameSiteStrictMode)
}

// startFlow remembers f for this browser, in place of any flow it had,
// and forgets every flow older than flowLifetime.
func (s *Server) startFlow(w http.ResponseWriter, f *flow) {
	id := rand.Text()
	now := s.cfg.Now()
	f.started = now
	s.mu.Lock()
	for k, old := range s.flows {
		if now.Sub(old.started) >= flowLifetime {
			delete(s.flows, k)
		}
	}
	s.flows[id] = f
	s.mu.Unlock()
	setCookie(w, flowCookie, id, int(flowLifetime/time.Second), http.SameSiteLaxMode)
}

// endFlow returns the flow r's cookie names, if there is one not older
// than flowLifetime, and it matches; and forgets it, so that it is used
// once, and removes the cookie. A flow that does not match is kept.
func (s *Server) endFlow(w http.ResponseWriter, r *http.Request, matches func(*flow) bool) *flow {
	c, err := r.Cookie(flowCookie)
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.flows[c.Value]
	if !ok || s.cfg.Now().Sub(f.started) >= flowLifetime || !matches(f) {
		return nil
	}
	delete(s.flows, c.Value)
	setCookie(w, flowCookie, "", -1, http.SameSiteLaxMode)
	return f
}

// setCookie sets the cookie name, as RFC 10017 §6.1.3.2 says: Secure,
// HttpOnly, Path=/ and no Domain. maxAge 0 makes it last until the browser
// closes, and a negative one removes it. sameSite is Strict or Lax, as
// each cookie's comment says.
func setCookie(w http.ResponseWriter, name, value string, maxAge int, sameSite http.SameSite) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure and HttpOnly are set; SameSite is each caller's Strict or Lax.
		Name: name, Value: value, Path: "/", MaxAge: maxAge,
		Secure: true, HttpOnly: true, SameSite: sameSite,
	})
}

// The web app's pages.
var (
	homePage = template.Must(template.New("home").Parse(page("", `
{{- if .}}
<p id="signed-in">Signed in as {{.}}.</p>
<p><a href="/notes">Your notes</a></p>
<form method="post" action="/logout"><p><button type="submit">Sign out</button></p></form>
{{- else}}
<p>You are not signed in. <a href="/login">Sign in</a></p>
{{- end}}`)))
	signedInPage = template.Must(template.New("signed in").Parse(page(`
<meta http-equiv="refresh" content="0; url=/">`, `
<p>Signed in. <a href="/">Continue</a></p>`)))
	notesPage = template.Must(template.New("notes").Parse(page("", `
<ul id="notes">
{{- range .}}
<li>{{.}}</li>
{{- end}}
</ul>
<form method="post" action="/notes">
<p><label>Note <input name="text" required></label> <button type="submit">Add</button></p>
</form>
<p><a href="/">Home</a></p>`)))
	signedOutPage = template.Must(template.New("signed out").Parse(page("", `
<p id="signed-out">You are signed out of the web app.</p>
<p><a href="/">Home</a></p>`)))
	messagePage = template.Must(template.New("message").Parse(page("", `
<p id="message">{{.}}</p>
<p><a href="/">Home</a></p>`)))
)

// page returns the web app's page, with head added to its head, and body
// as its body.
func page(head, body string) string {
	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>The web app example</title>` + head + `
</head>
<body>
<main>` + body + `
</main>
</body>
</html>
`
}

// render answers with status and t, executed with data.
func render(w http.ResponseWriter, status int, t *template.Template, data any) {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes()) // The status is already sent; a failed write has no one to tell.
}

// message answers with status and a page that says msg.
func message(w http.ResponseWriter, status int, msg string) {
	render(w, status, messagePage, msg)
}
