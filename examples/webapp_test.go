package examples_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
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
// consent and calls to the API; two refreshes, each once the access token
// has expired by the web app's clock; and a logout, which the End-User
// confirms on pulsar's page, back to the web app with its state.
//
// pulsar issues a refresh token for offline_access (REQ-CORE-52), and
// rotates it on each refresh (REQ-BCP-9), with an access token the API
// accepts, for the Resource Server of the sign-in (REQ-BCP-8). The web
// app's logout revokes its refresh token, which pulsar then refuses
// (REQ-REVOKE-1, REQ-REVOKE-8), and sends the End-User to pulsar's logout
// endpoint with id_token_hint (REQ-LOGOUT-2). pulsar asks them to confirm
// (REQ-LOGOUT-8), ends their Login Session, so that prompt=none gets
// login_required (REQ-CORE-14, REQ-CORE-29), and returns them to the
// registered post_logout_redirect_uri with the state (REQ-LOGOUT-5,
// REQ-LOGOUT-6).
//
// Throughout, the browser receives no access or refresh token, and the ID
// token only as the id_token_hint of the logout request, in the web app's
// redirect to pulsar and in pulsar's own logout page.
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

	// Sign-in and consent, then a note added and listed through the API.
	toAuthorize, err := b.step(ctx, http.MethodGet, webAppURL+"/login", nil)
	if err != nil || toAuthorize.status != http.StatusSeeOther {
		t.Fatalf("GET /login: status %d, error %v; want 303 to pulsar", toAuthorize.status, err)
	}
	// A response with another state is refused, and leaves the sign-in to
	// finish.
	forgedCallback, err := b.step(ctx, http.MethodGet, webAppURL+"/callback?code=forged&state=forged", nil)
	if err != nil || forgedCallback.status != http.StatusBadRequest {
		t.Errorf("GET /callback with another state: status %d, error %v; want 400", forgedCallback.status, err)
	}
	callback, err := b.visit(ctx, http.MethodGet, toAuthorize.header.Get("Location"), nil)
	if err != nil {
		t.Fatalf("sign in: error = %v, want nil", err)
	}
	if callback.url.Path != "/callback" || callback.status != http.StatusOK || !strings.Contains(callback.body, `<meta http-equiv="refresh" content="0; url=/">`) {
		t.Fatalf("sign in: ended at %s, status %d: %s; want the redirect URI, 200, refreshing to /", callback.url, callback.status, callback.body)
	}
	// The page's refresh, a navigation from the web app's own page.
	home, err := b.send(ctx, http.MethodGet, webAppURL+"/", nil)
	if err != nil || home.status != http.StatusOK || !strings.Contains(home.body, "Signed in as "+subject) {
		t.Fatalf("GET / after sign-in: status %d, error %v: %s; want 200, naming %s", home.status, err, home.body, subject)
	}
	if got := b.client.Jar.Cookies(home.url); len(got) != 1 {
		t.Errorf("after sign-in, the browser holds cookies %v for the web app, want its one session cookie", got)
	}
	notes, err := b.visit(ctx, http.MethodPost, webAppURL+"/notes", url.Values{"text": {"buy milk"}})
	if err != nil || notes.status != http.StatusOK || !strings.Contains(notes.body, "buy milk") {
		t.Fatalf("POST /notes: status %d, error %v: %s; want 200, listing buy milk", notes.status, err, notes.body)
	}
	issued := tokens.responses()
	if len(issued) != 1 {
		t.Fatalf("after sign-in, the web app got %d token responses, want 1", len(issued))
	}
	signIn := issued[0]
	if signIn.RefreshToken == "" {
		t.Error("the token response to sign-in has no refresh_token, want one for offline_access")
	}

	// The access token expires by the web app's clock; listing the notes
	// again makes the web app refresh it, and the API accepts the new one.
	// Twice, since the second refresh works only with the refresh token
	// the first returned: pulsar takes the one it replaced, presented
	// again, as stolen.
	for i := range 2 {
		ahead.Add(int64(time.Duration(signIn.ExpiresIn) * time.Second))
		notes, err = b.visit(ctx, http.MethodGet, webAppURL+"/notes", nil)
		if err != nil || notes.status != http.StatusOK || !strings.Contains(notes.body, "buy milk") {
			t.Fatalf("GET /notes after the access token expired, refresh %d: status %d, error %v: %s; want 200, listing buy milk", i+1, notes.status, err, notes.body)
		}
		issued = tokens.responses()
		if len(issued) != i+2 {
			t.Fatalf("after the access token expired, refresh %d: the web app got %d token responses, want %d", i+1, len(issued), i+2)
		}
		before, after := issued[i], issued[i+1]
		if after.RefreshToken == "" || after.RefreshToken == before.RefreshToken {
			t.Errorf("refresh %d: refresh_token = %q, want a new one, not %q", i+1, after.RefreshToken, before.RefreshToken)
		}
		if after.AccessToken == before.AccessToken {
			t.Errorf("refresh %d: access_token is the one before, want a new one", i+1)
		}
	}
	refreshed := issued[len(issued)-1]

	// Logout: the web app sends the browser to pulsar's logout endpoint.
	toPulsar, err := b.step(ctx, http.MethodPost, webAppURL+"/logout", url.Values{})
	if err != nil {
		t.Fatalf("POST /logout error = %v, want nil", err)
	}
	logoutReq, err := url.Parse(toPulsar.header.Get("Location"))
	if toPulsar.status != http.StatusSeeOther || err != nil {
		t.Fatalf("POST /logout = %d, Location %q; want 303 to pulsar's end_session_endpoint", toPulsar.status, toPulsar.header.Get("Location"))
	}
	q := logoutReq.Query()
	state := q.Get("state")
	endpoint := *logoutReq
	endpoint.RawQuery = ""
	if endpoint.String() != meta.EndSessionEndpoint ||
		q.Get("id_token_hint") != signIn.IDToken || q.Get("post_logout_redirect_uri") != webAppURL+"/signed-out" || state == "" {
		t.Errorf("POST /logout redirects to %s, want %s with the ID token from sign-in as id_token_hint, post_logout_redirect_uri %s/signed-out, and a state",
			logoutReq, meta.EndSessionEndpoint, webAppURL)
	}

	// A return with another state is refused, and leaves the logout to
	// finish.
	forged, err := b.step(ctx, http.MethodGet, webAppURL+"/signed-out?state=forged", nil)
	if err != nil || forged.status != http.StatusBadRequest {
		t.Errorf("GET /signed-out with another state: status %d, error %v; want 400", forged.status, err)
	}

	// The End-User confirms on pulsar's page, and returns with the state.
	signedOut, err := b.visit(ctx, http.MethodGet, logoutReq.String(), nil)
	if err != nil {
		t.Fatalf("log out at pulsar: error = %v, want nil", err)
	}
	want := webAppURL + "/signed-out?" + url.Values{"state": {state}}.Encode()
	if signedOut.url.String() != want || signedOut.status != http.StatusOK {
		t.Errorf("log out at pulsar: ended at %s, status %d; want %s, 200", signedOut.url, signedOut.status, want)
	}

	// The refresh token the web app held when it logged out, never
	// redeemed, is refused: it was revoked.
	if got := redeemRefreshToken(t, meta.TokenEndpoint, refreshed.RefreshToken); got != "invalid_grant" {
		t.Errorf("the web app's refresh token, after logout: error = %q, want invalid_grant", got)
	}

	// The browser's Login Session at pulsar has ended.
	authorize := oauth2.Config{
		ClientID:    webAppClientID,
		Endpoint:    oauth2.Endpoint{AuthURL: meta.AuthorizationEndpoint},
		RedirectURL: webAppURL + "/callback",
		Scopes:      []string{"openid"},
	}
	silent, err := b.step(ctx, http.MethodGet, authorize.AuthCodeURL("silent", oauth2.S256ChallengeOption(oauth2.GenerateVerifier()), oauth2.SetAuthURLParam("prompt", "none")), nil)
	if err != nil {
		t.Fatalf("prompt=none after logout: error = %v, want nil", err)
	}
	back, err := url.Parse(silent.header.Get("Location"))
	if err != nil || !strings.HasPrefix(back.String(), webAppURL+"/callback?") || back.Query().Get("error") != "login_required" || back.Query().Get("state") != "silent" {
		t.Errorf("prompt=none after logout: %d, Location %q; want a redirect to %s/callback with error login_required and state silent",
			silent.status, silent.header.Get("Location"), webAppURL)
	}

	// No token reached the browser, but for the ID token as id_token_hint.
	for _, resp := range b.recorder.received() {
		for _, tr := range issued {
			for name, token := range map[string]string{"access token": tr.AccessToken, "refresh token": tr.RefreshToken, "ID token": tr.IDToken} {
				if token == "" || !resp.holds(token) {
					continue
				}
				asHint := token == signIn.IDToken &&
					(resp.url.String() == webAppURL+"/logout" || strings.HasPrefix(resp.url.String(), meta.EndSessionEndpoint))
				if !asHint {
					t.Errorf("the browser received an %s in the response %d from %s", name, resp.status, resp.url)
				}
			}
		}
	}
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
	var meta metadata
	if status := pulsarJSON(t, http.MethodGet, issuer+"/.well-known/openid-configuration", nil, &meta); status != http.StatusOK {
		t.Fatalf("pulsar's discovery document: status %d, want 200", status)
	}
	return meta
}

// redeemRefreshToken sends refreshToken to the token endpoint, as the web
// app would, and returns the error code of the response; "" if there is
// none.
func redeemRefreshToken(t *testing.T, tokenEndpoint, refreshToken string) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
	pulsarJSON(t, http.MethodPost, tokenEndpoint, form, &body)
	return body.Error
}

// pulsarJSON sends a request to pulsar, a POST with form as its body and the
// web app's credentials, and decodes the response's JSON body into out. It
// returns the response's status.
func pulsarJSON(t *testing.T, method, rawURL string, form url.Values, out any) int {
	t.Helper()
	var body io.Reader = http.NoBody
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(t.Context(), method, rawURL, body)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext() error = %v, want nil", err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(url.QueryEscape(webAppClientID), url.QueryEscape(webAppSecret))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s error = %v, want nil", method, rawURL, err)
	}
	defer resp.Body.Close() //nolint:errcheck // Closing a response body reports nothing to act on.
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("%s %s: the body is not JSON: %v", method, rawURL, err)
	}
	return resp.StatusCode
}

// holds reports whether s appears in r's headers or body.
func (r response) holds(s string) bool {
	if strings.Contains(r.body, s) {
		return true
	}
	for _, values := range r.header {
		for _, v := range values {
			if strings.Contains(v, s) {
				return true
			}
		}
	}
	return false
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
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
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
	return append([]tokenResponse(nil), r.tokens...)
}
