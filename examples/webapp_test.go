package examples_test

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/palebluedot4/pulsar/examples/webapp"
)

// What registry.json registers for the web app: a confidential Client,
// whose secret, like the End-User's password, is published deliberately,
// for this stack only (SECURITY.md). Its redirect URI and post-logout
// redirect URI are under webAppURL, where the test serves it.
const (
	webAppClientID = "webapp"
	webAppSecret   = "fXVx4UH6F0awyDIESJsM21sLdOr_SDTYmQfHerTUPPY" //nolint:gosec // G101: published deliberately, for this stack only (SECURITY.md).
	webAppAddr     = "localhost:8082"
	webAppURL      = "http://" + webAppAddr
)

// TestWebApp drives the web app as the End-User's browser would: sign-in,
// on pulsar's login and consent pages, and calls to the API; two
// refreshes, each once the access token has expired by the web app's
// clock; a second sign-in, which replaces the session; and a logout,
// which the End-User confirms on pulsar's logout page, back to the web
// app with its state.
//
// pulsar issues a refresh token for offline_access (REQ-CORE-52), and
// rotates it on each refresh (REQ-BCP-9), with an access token the API
// accepts, for the Resource Server of the sign-in (REQ-BCP-8). The second
// sign-in, and the logout, each revoke the session's refresh token, which
// pulsar then refuses (REQ-REVOKE-1, REQ-REVOKE-8). The logout sends the
// End-User to pulsar's logout endpoint with id_token_hint (REQ-LOGOUT-2). pulsar asks them to confirm
// (REQ-LOGOUT-8), ends their Login Session, so that prompt=none gets
// login_required (REQ-CORE-14, REQ-CORE-29), and returns them to the
// registered post_logout_redirect_uri with the state (REQ-LOGOUT-5,
// REQ-LOGOUT-6).
//
// No response the browser receives holds an access or refresh token, and
// the ID token appears only as id_token_hint: in the Location of the web
// app's redirect to pulsar's logout endpoint, and in the form of pulsar's
// logout page.
func TestWebApp(t *testing.T) {
	t.Parallel()

	meta := discover(t)
	tokens := &tokenRecorder{next: http.DefaultTransport}
	var ahead atomic.Int64 // how far the web app's clock is ahead of the clock
	app, err := webapp.New(t.Context(), webapp.Config{
		Issuer:        issuer,
		ClientID:      webAppClientID,
		ClientSecret:  webAppSecret,
		URL:           webAppURL,
		APIURL:        newAPI(t, nil).URL,
		APIIdentifier: identifier,
		HTTPClient:    &http.Client{Transport: tokens, Timeout: 30 * time.Second},
		Now:           func() time.Time { return time.Now().Add(time.Duration(ahead.Load())) },
	})
	if err != nil {
		t.Fatalf("webapp.New() error = %v, want nil", err)
	}
	serve(t, webAppAddr, app)
	b := newBrowser(t)
	ctx := t.Context()

	// The authorization request: PKCE by S256, state, nonce,
	// offline_access with prompt=consent, and resource.
	toAuthorize, err := b.fetch(ctx, http.MethodGet, webAppURL+"/login", nil)
	if err != nil {
		t.Fatalf("GET /login error = %v, want nil", err)
	}
	if toAuthorize.status != http.StatusSeeOther {
		t.Fatalf("GET /login status = %d, want %d", toAuthorize.status, http.StatusSeeOther)
	}
	authReq, err := url.Parse(toAuthorize.header.Get("Location"))
	if err != nil {
		t.Fatalf("GET /login Location = %q: %v", toAuthorize.header.Get("Location"), err)
	}
	if got := withoutQuery(authReq); got != meta.AuthorizationEndpoint {
		t.Errorf("GET /login redirects to %s, want %s", got, meta.AuthorizationEndpoint)
	}
	aq := authReq.Query()
	for name, want := range map[string]string{"code_challenge_method": "S256", "prompt": "consent", "resource": identifier} {
		if got := aq.Get(name); got != want {
			t.Errorf("GET /login authorization request %s = %q, want %q", name, got, want)
		}
	}
	for _, name := range []string{"code_challenge", "state", "nonce"} {
		if aq.Get(name) == "" {
			t.Errorf("GET /login authorization request %s = \"\", want one", name)
		}
	}
	if scopes := strings.Fields(aq.Get("scope")); !slices.Contains(scopes, "offline_access") {
		t.Errorf("GET /login authorization request scope = %q, want it to hold offline_access", aq.Get("scope"))
	}

	// A response with another state is refused, and leaves the sign-in to
	// finish.
	forgedCallback, err := b.fetch(ctx, http.MethodGet, webAppURL+"/callback?code=forged&state=forged", nil)
	if err != nil {
		t.Fatalf("GET /callback with another state: error = %v, want nil", err)
	}
	if forgedCallback.status != http.StatusBadRequest {
		t.Errorf("GET /callback with another state: status = %d, want %d", forgedCallback.status, http.StatusBadRequest)
	}

	// Sign-in, on pulsar's login and consent pages.
	callback, answered, err := b.visit(ctx, http.MethodGet, authReq.String(), nil)
	if err != nil {
		t.Fatalf("sign in at pulsar: error = %v, want nil", err)
	}
	if want := []string{loginPage, consentPage}; !slices.Equal(answered, want) {
		t.Errorf("sign in at pulsar: answered pages %q, want %q", answered, want)
	}
	if callback.url.Path != "/callback" || callback.status != http.StatusOK {
		t.Fatalf("sign in at pulsar: ended at %s, status %d; want %s/callback, %d", callback.url, callback.status, webAppURL, http.StatusOK)
	}
	if refresh := `<meta http-equiv="refresh" content="0; url=/">`; !strings.Contains(callback.body, refresh) {
		t.Errorf("GET /callback body = %s, want it to hold %s", callback.body, refresh)
	}
	// The page's refresh, a navigation from the web app's own page.
	home := get(t, b, webAppURL+"/")
	if want := "Signed in as " + subject; !strings.Contains(home.body, want) {
		t.Fatalf("GET / after sign-in: body = %s, want it to hold %q", home.body, want)
	}
	if got := b.client.Jar.Cookies(home.url); len(got) != 1 {
		t.Errorf("after sign-in, the browser's cookies for the web app = %v, want its one session cookie", got)
	}

	// A note added and listed through the API.
	notes, _, err := b.visit(ctx, http.MethodPost, webAppURL+"/notes", url.Values{"text": {"buy milk"}})
	if err != nil {
		t.Fatalf("POST /notes error = %v, want nil", err)
	}
	if notes.status != http.StatusOK || !strings.Contains(notes.body, "buy milk") {
		t.Fatalf("POST /notes, then its redirect: status = %d, body = %s; want %d, listing buy milk", notes.status, notes.body, http.StatusOK)
	}
	issued := tokens.responses()
	if len(issued) != 1 {
		t.Fatalf("after sign-in, the web app's token responses = %d, want 1", len(issued))
	}
	signIn := issued[0]
	if signIn.RefreshToken == "" {
		t.Error(`the token response to sign-in: refresh_token = "", want one for offline_access`)
	}

	// The access token expires by the web app's clock; listing the notes
	// again makes the web app refresh it, and the API accepts the new one.
	// Twice, since the second refresh works only with the refresh token
	// the first returned: pulsar takes the one it replaced, presented
	// again, as stolen.
	for i := range 2 {
		ahead.Add(int64(time.Duration(signIn.ExpiresIn) * time.Second))
		listed := get(t, b, webAppURL+"/notes")
		if !strings.Contains(listed.body, "buy milk") {
			t.Fatalf("GET /notes after the access token expired, refresh %d: body = %s, want it to list buy milk", i+1, listed.body)
		}
		issued = tokens.responses()
		if len(issued) != i+2 {
			t.Fatalf("after the access token expired, refresh %d: the web app's token responses = %d, want %d", i+1, len(issued), i+2)
		}
		before, after := issued[i], issued[i+1]
		if after.RefreshToken == "" || after.RefreshToken == before.RefreshToken {
			t.Errorf("refresh %d: refresh_token = %q, want a new one, not %q", i+1, after.RefreshToken, before.RefreshToken)
		}
		if after.AccessToken == before.AccessToken {
			t.Errorf("refresh %d: access_token = the one before, want a new one", i+1)
		}
	}
	refreshed := issued[len(issued)-1]

	// Signing in again in the same browser replaces the session: the web
	// app revokes the refresh token of the one it had (REQ-REVOKE-1). The
	// Login Session at pulsar remains, so only the consent page is shown.
	// The web app's clock is set back first, since it checks the new ID
	// token's exp by it.
	ahead.Store(0)
	callback, answered, err = b.visit(ctx, http.MethodGet, webAppURL+"/login", nil)
	if err != nil {
		t.Fatalf("sign in again: error = %v, want nil", err)
	}
	if want := []string{consentPage}; !slices.Equal(answered, want) {
		t.Errorf("sign in again: answered pages %q, want %q", answered, want)
	}
	if callback.url.Path != "/callback" || callback.status != http.StatusOK {
		t.Fatalf("sign in again: ended at %s, status %d: %s; want %s/callback, %d", callback.url, callback.status, callback.body, webAppURL, http.StatusOK)
	}
	issued = tokens.responses()
	if len(issued) != 4 {
		t.Fatalf("after signing in again, the web app's token responses = %d, want 4", len(issued))
	}
	again := issued[3]
	if got := redeemRefreshToken(t, meta.TokenEndpoint, refreshed.RefreshToken); got != "invalid_grant" {
		t.Errorf("redeemRefreshToken(the replaced session's last refresh token) = %q, want %q", got, "invalid_grant")
	}
	if listed := get(t, b, webAppURL+"/notes"); !strings.Contains(listed.body, "buy milk") {
		t.Errorf("GET /notes in the new session: body = %s, want it to list buy milk", listed.body)
	}
	if got := b.client.Jar.Cookies(home.url); len(got) != 1 {
		t.Errorf("after signing in again, the browser's cookies for the web app = %v, want its one session cookie", got)
	}

	// Logout: the web app sends the browser to pulsar's logout endpoint.
	toPulsar, err := b.fetch(ctx, http.MethodPost, webAppURL+"/logout", url.Values{})
	if err != nil {
		t.Fatalf("POST /logout error = %v, want nil", err)
	}
	if toPulsar.status != http.StatusSeeOther {
		t.Fatalf("POST /logout status = %d, want %d", toPulsar.status, http.StatusSeeOther)
	}
	logoutReq, err := url.Parse(toPulsar.header.Get("Location"))
	if err != nil {
		t.Fatalf("POST /logout Location = %q: %v", toPulsar.header.Get("Location"), err)
	}
	if got := withoutQuery(logoutReq); got != meta.EndSessionEndpoint {
		t.Errorf("POST /logout redirects to %s, want %s", got, meta.EndSessionEndpoint)
	}
	lq := logoutReq.Query()
	if lq.Get("id_token_hint") != again.IDToken {
		t.Errorf("POST /logout logout request id_token_hint = %q, want the ID token of the session's sign-in, %q", lq.Get("id_token_hint"), again.IDToken)
	}
	if got, want := lq.Get("post_logout_redirect_uri"), webAppURL+"/signed-out"; got != want {
		t.Errorf("POST /logout logout request post_logout_redirect_uri = %q, want %q", got, want)
	}
	state := lq.Get("state")
	if state == "" {
		t.Error(`POST /logout logout request state = "", want one`)
	}

	// A return with another state is refused, and leaves the logout to
	// finish.
	forged, err := b.fetch(ctx, http.MethodGet, webAppURL+"/signed-out?state=forged", nil)
	if err != nil {
		t.Fatalf("GET /signed-out with another state: error = %v, want nil", err)
	}
	if forged.status != http.StatusBadRequest {
		t.Errorf("GET /signed-out with another state: status = %d, want %d", forged.status, http.StatusBadRequest)
	}

	// The End-User confirms on pulsar's logout page, and returns with the
	// state.
	signedOut, answered, err := b.visit(ctx, http.MethodGet, logoutReq.String(), nil)
	if err != nil {
		t.Fatalf("log out at pulsar: error = %v, want nil", err)
	}
	if want := []string{logoutPage}; !slices.Equal(answered, want) {
		t.Errorf("log out at pulsar: answered pages %q, want %q", answered, want)
	}
	want := webAppURL + "/signed-out?" + url.Values{"state": {state}}.Encode()
	if signedOut.url.String() != want || signedOut.status != http.StatusOK {
		t.Errorf("log out at pulsar: ended at %s, status %d; want %s, %d", signedOut.url, signedOut.status, want, http.StatusOK)
	}

	// The refresh token the web app held when it logged out, never
	// redeemed, is refused: it was revoked.
	if got := redeemRefreshToken(t, meta.TokenEndpoint, again.RefreshToken); got != "invalid_grant" {
		t.Errorf("redeemRefreshToken(the web app's last refresh token, after logout) = %q, want %q", got, "invalid_grant")
	}

	// The browser's Login Session at pulsar has ended.
	authorize := oauth2.Config{
		ClientID:    webAppClientID,
		Endpoint:    oauth2.Endpoint{AuthURL: meta.AuthorizationEndpoint},
		RedirectURL: webAppURL + "/callback",
		Scopes:      []string{"openid"},
	}
	silent, err := b.fetch(ctx, http.MethodGet, authorize.AuthCodeURL("silent", oauth2.S256ChallengeOption(oauth2.GenerateVerifier()), oauth2.SetAuthURLParam("prompt", "none")), nil)
	if err != nil {
		t.Fatalf("prompt=none after logout: error = %v, want nil", err)
	}
	back, err := url.Parse(silent.header.Get("Location"))
	if err != nil {
		t.Fatalf("prompt=none after logout: Location = %q: %v", silent.header.Get("Location"), err)
	}
	if got := withoutQuery(back); got != webAppURL+"/callback" {
		t.Errorf("prompt=none after logout: redirects to %s, want %s/callback", got, webAppURL)
	}
	if got := back.Query().Get("error"); got != "login_required" {
		t.Errorf("prompt=none after logout: error = %q, want %q", got, "login_required")
	}
	if got := back.Query().Get("state"); got != "silent" {
		t.Errorf("prompt=none after logout: state = %q, want %q", got, "silent")
	}

	// No token reached the browser, but for the ID token as id_token_hint,
	// where the logout request carries it.
	for _, p := range b.recorder.received() {
		for _, tr := range issued {
			for name, token := range map[string]string{"access token": tr.AccessToken, "refresh token": tr.RefreshToken, "ID token": tr.IDToken} {
				rest := p
				if token == again.IDToken {
					rest = withoutHint(p, token, meta.EndSessionEndpoint)
				}
				if token != "" && rest.holds(token) {
					t.Errorf("the response %d from %s holds an %s", p.status, p.url, name)
				}
			}
		}
	}
}

// get gets rawURL in b, following redirects but answering none of
// pulsar's pages, and returns the page, which must answer 200.
func get(t *testing.T, b *browser, rawURL string) page {
	t.Helper()
	p, answered, err := b.visit(t.Context(), http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("GET %s error = %v, want nil", rawURL, err)
	}
	if len(answered) != 0 {
		t.Fatalf("GET %s: answered pages %q, want none", rawURL, answered)
	}
	if p.status != http.StatusOK {
		t.Fatalf("GET %s status = %d, want %d; body: %s", rawURL, p.status, http.StatusOK, p.body)
	}
	return p
}

// withoutHint returns p without the places the logout request carries
// idToken as id_token_hint: the parameter of the Location of the web app's
// redirect to endSession, the logout endpoint, and the hidden field of
// the form of pulsar's logout page there. Anything else of p is as it was.
func withoutHint(p page, idToken, endSession string) page {
	switch withoutQuery(p.url) {
	case webAppURL + "/logout":
		u, err := url.Parse(p.header.Get("Location"))
		if err != nil || withoutQuery(u) != endSession {
			return p
		}
		q := u.Query()
		if q.Get("id_token_hint") != idToken {
			return p
		}
		q.Del("id_token_hint")
		u.RawQuery = q.Encode()
		p.header = p.header.Clone()
		p.header.Set("Location", u.String())
	case endSession:
		p.body = strings.ReplaceAll(p.body, `<input type="hidden" name="id_token_hint" value="`+idToken+`">`, "")
	}
	return p
}

// withoutQuery returns u as a string, without its query.
func withoutQuery(u *url.URL) string {
	v := *u
	v.RawQuery = ""
	return v.String()
}

// serve serves handler at addr until the test ends.
func serve(t *testing.T, addr string, handler http.Handler) {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatalf("listen on %s: error = %v, want nil", addr, err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
}

// metadata is what the test reads of pulsar's discovery document.
type metadata struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// discover returns pulsar's discovery document.
func discover(t *testing.T) metadata {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, issuer+"/.well-known/openid-configuration", http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext() error = %v, want nil", err)
	}
	var meta metadata
	if status := doJSON(t, req, &meta); status != http.StatusOK {
		t.Fatalf("GET %s status = %d, want %d", req.URL, status, http.StatusOK)
	}
	return meta
}

// redeemRefreshToken sends refreshToken to the token endpoint with the web
// app's credentials, as the web app would, and returns the error code of
// the response; "" if there is none.
func redeemRefreshToken(t *testing.T, tokenEndpoint, refreshToken string) string {
	t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("http.NewRequestWithContext() error = %v, want nil", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(webAppClientID), url.QueryEscape(webAppSecret))
	var body struct {
		Error string `json:"error"`
	}
	doJSON(t, req, &body)
	return body.Error
}

// doJSON sends req, and decodes the response's JSON body into out. It
// returns the response's status.
func doJSON(t *testing.T, req *http.Request, out any) int {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s error = %v, want nil", req.Method, req.URL, err)
	}
	defer resp.Body.Close() //nolint:errcheck // Closing a response body reports nothing to act on.
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("%s %s: decoding the body as JSON: error = %v, want nil", req.Method, req.URL, err)
	}
	return resp.StatusCode
}

// tokenResponse is a successful token response, as the web app received
// it from pulsar's token endpoint.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// tokenRecorder is the web app's http.RoundTripper: it records the token
// responses next returns, and passes every response on unchanged.
type tokenRecorder struct {
	next http.RoundTripper

	mu     sync.Mutex
	tokens []tokenResponse
}

func (r *tokenRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	body, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	var tr tokenResponse
	if json.Unmarshal(body, &tr) == nil && tr.AccessToken != "" {
		r.mu.Lock()
		r.tokens = append(r.tokens, tr)
		r.mu.Unlock()
	}
	return resp, nil
}

// responses returns the token responses recorded so far.
func (r *tokenRecorder) responses() []tokenResponse {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.tokens)
}
