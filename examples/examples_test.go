// The examples' tests run the web app, the CLI and the API against a
// pulsar that make examples starts in Docker Compose, with registry.json.
// They reach pulsar only by its URL, and act as the End-User's browser
// through its login, consent and logout pages. They serve the web app at
// localhost:8082, under which registry.json registers its redirect URIs,
// so that port must be free. The environment names that pulsar:
//
//	PULSAR_EXAMPLES_ISSUER  its issuer, which serves on the host
//	PULSAR_EXAMPLES_ROTATE  a shell command that runs `pulsar keys rotate` against it
//
// They wait on a real pulsar's clock, so they use the clock rather than
// testing/synctest, and take a few minutes: a rotated key signs two
// minutes after it is stored. They compare with slices.Equal and ==
// rather than cmp.Diff, as AGENTS.md has tests do, since the module
// requires only the three libraries the examples show.
package examples_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/palebluedot4/pulsar/examples/api"
	"github.com/palebluedot4/pulsar/examples/cli"
)

// What registry.json registers: the CLI's Client, the API's Resource
// Server, and the End-User, whose password examples/README.md publishes.
const (
	clientID   = "cli"
	identifier = "https://api.example/notes"
	username   = "example"
	password   = "examples-password" // published deliberately, for this stack only (SECURITY.md)
	subject    = "6f8909cd-26ca-49d5-bd35-8f34d427aa73"
)

// issuer is pulsar's issuer, from PULSAR_EXAMPLES_ISSUER.
var issuer string

func TestMain(m *testing.M) {
	issuer = os.Getenv("PULSAR_EXAMPLES_ISSUER")
	if issuer == "" {
		fmt.Fprintln(os.Stderr, "PULSAR_EXAMPLES_ISSUER is not set; run the examples' tests through make examples, which starts pulsar")
		os.Exit(1)
	}
	if err := waitReady(issuer); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// waitReady waits for pulsar's /readyz to answer 200, as it does once
// pulsar has migrated its database and loaded its signing keys.
func waitReady(issuer string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/readyz", http.NoBody)
		if err != nil {
			return err
		}
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("pulsar at %s is not ready: %w", issuer, ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

// TestCLICallsAPI: the CLI signs the End-User in through a loopback
// redirect on a port the operating system chose, gets an access token for
// the API by the resource parameter, and calls the API with it. pulsar
// accepts the CLI's loopback redirect URI with that port (REQ-NATIVE-1),
// and the API accepts the token, whose aud is its identifier
// (REQ-RESOURCE-3, REQ-AT-12).
func TestCLICallsAPI(t *testing.T) {
	t.Parallel()

	srv := newAPI(t, nil)
	writer := signIn(t, identifier, api.ScopeWrite)
	if writer.Subject != subject {
		t.Errorf("cli.SignIn() Subject = %q, want %q", writer.Subject, subject)
	}
	if err := cli.AddNote(t.Context(), srv.URL, writer.AccessToken, "buy milk"); err != nil {
		t.Fatalf("cli.AddNote() error = %v, want nil", err)
	}

	reader := signIn(t, identifier, api.ScopeRead)
	got, err := cli.ListNotes(t.Context(), srv.URL, reader.AccessToken)
	if err != nil {
		t.Fatalf("cli.ListNotes() error = %v, want nil", err)
	}
	if want := []string{"buy milk"}; !slices.Equal(got, want) {
		t.Errorf("cli.ListNotes() = %q, want %q", got, want)
	}
}

// TestAPIRefuses: the API answers a request without a valid access token
// for it with 401 and a Bearer challenge, with invalid_token when a token
// was sent (RFC 6750 §3.1), and a valid token without the route's scope
// with 403 and insufficient_scope.
func TestAPIRefuses(t *testing.T) {
	t.Parallel()

	reader := signIn(t, identifier, api.ScopeRead)
	forUserInfo := signIn(t, "", "profile")
	exp := expiry(t, reader.AccessToken)

	srv := newAPI(t, nil)
	atExp := newAPI(t, func() time.Time { return exp })
	beforeExp := newAPI(t, func() time.Time { return exp.Add(-time.Second) })

	const invalid = `Bearer error="invalid_token", error_description="The access token is invalid."`
	tests := []struct {
		name          string
		api           *httptest.Server
		method        string
		authorization string
		wantStatus    int
		wantChallenge string
	}{
		{name: "valid, for comparison", api: srv, method: http.MethodGet, authorization: "Bearer " + reader.AccessToken, wantStatus: http.StatusOK},
		{name: "valid, a second before exp", api: beforeExp, method: http.MethodGet, authorization: "Bearer " + reader.AccessToken, wantStatus: http.StatusOK},
		{name: "no token", api: srv, method: http.MethodGet, wantStatus: http.StatusUnauthorized, wantChallenge: "Bearer"},
		{name: "another scheme", api: srv, method: http.MethodGet, authorization: "Basic Y2xpOg==", wantStatus: http.StatusUnauthorized, wantChallenge: "Bearer"},
		{
			name: "a token for pulsar's UserInfo", api: srv, method: http.MethodGet, authorization: "Bearer " + forUserInfo.AccessToken,
			wantStatus: http.StatusUnauthorized, wantChallenge: invalid,
		},
		{
			name: "expired, at exp", api: atExp, method: http.MethodGet, authorization: "Bearer " + reader.AccessToken,
			wantStatus: http.StatusUnauthorized, wantChallenge: invalid,
		},
		{
			name: "tampered: a scope added", api: srv, method: http.MethodPost, authorization: "Bearer " + withScope(t, reader.AccessToken, api.ScopeRead+" "+api.ScopeWrite),
			wantStatus: http.StatusUnauthorized, wantChallenge: invalid,
		},
		{
			name: "unsigned, alg none", api: srv, method: http.MethodGet, authorization: "Bearer " + unsigned(t, reader.AccessToken),
			wantStatus: http.StatusUnauthorized, wantChallenge: invalid,
		},
		{
			name: "an ID token", api: srv, method: http.MethodGet, authorization: "Bearer " + reader.IDToken,
			wantStatus: http.StatusUnauthorized, wantChallenge: invalid,
		},
		{
			name: "without the route's scope", api: srv, method: http.MethodPost, authorization: "Bearer " + reader.AccessToken,
			wantStatus: http.StatusForbidden, wantChallenge: `Bearer error="insufficient_scope", scope="notes:write"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req, err := http.NewRequestWithContext(t.Context(), tt.method, tt.api.URL+"/notes", strings.NewReader(`{"text": "a note"}`))
			if err != nil {
				t.Fatalf("http.NewRequestWithContext() error = %v, want nil", err)
			}
			if tt.authorization != "" {
				req.Header.Set("Authorization", tt.authorization)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("%s /notes error = %v, want nil", tt.method, err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("%s /notes status = %d, want %d", tt.method, resp.StatusCode, tt.wantStatus)
			}
			if got := resp.Header.Get("WWW-Authenticate"); got != tt.wantChallenge {
				t.Errorf("%s /notes WWW-Authenticate = %q, want %q", tt.method, got, tt.wantChallenge)
			}
		})
	}
}

// TestAPIKeysUnreachable: a token the API cannot verify because pulsar's
// JWK Set cannot be reached gets 503, not invalid_token, which would tell
// the Client to discard a token that may be valid (RFC 6750 §3.1).
func TestAPIKeysUnreachable(t *testing.T) {
	t.Parallel()

	// An issuer whose discovery document names a JWK Set at a port
	// nothing listens on: one a listener just released.
	closed := httptest.NewServer(http.NotFoundHandler())
	jwksURI := closed.URL + "/jwks"
	closed.Close()
	var discovery *httptest.Server
	discovery = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"issuer": %q, "jwks_uri": %q}`, discovery.URL, jwksURI)
	}))
	t.Cleanup(discovery.Close)
	handler, err := api.New(t.Context(), api.Config{Issuer: discovery.URL, Identifier: identifier})
	if err != nil {
		t.Fatalf("api.New() error = %v, want nil", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	reader := signIn(t, identifier, api.ScopeRead)
	_, err = cli.ListNotes(t.Context(), srv.URL, reader.AccessToken)
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Errorf("cli.ListNotes() with pulsar's JWK Set unreachable error = %v, want the API's 503", err)
	}
}

// TestAPIAfterKeyRotation: after `pulsar keys rotate`, once pulsar signs
// with the new key, the API, which cached pulsar's JWK Set before the
// rotation, fetches it again for the new key and accepts the token it
// signed, and still accepts one the old key signed.
func TestAPIAfterKeyRotation(t *testing.T) {
	t.Parallel()

	rotate := os.Getenv("PULSAR_EXAMPLES_ROTATE")
	if rotate == "" {
		t.Fatal("PULSAR_EXAMPLES_ROTATE is not set; run the examples' tests through make examples")
	}
	srv := newAPI(t, nil)
	before := signIn(t, identifier, api.ScopeRead)
	if _, err := cli.ListNotes(t.Context(), srv.URL, before.AccessToken); err != nil {
		t.Fatalf("before the rotation: cli.ListNotes() error = %v, want nil", err)
	}
	oldKID := keyID(t, before.AccessToken)

	out, err := exec.CommandContext(t.Context(), "sh", "-c", rotate).Output() //nolint:gosec // G204: the command make examples gives, run as the operator would.
	if err != nil {
		t.Fatalf("sh -c %q: error = %v, want nil", rotate, err)
	}
	newKID, signsFrom := storedKey(t, out)
	if newKID == oldKID {
		t.Fatalf("pulsar keys rotate stored kid %q, the one already signing", newKID)
	}
	t.Logf("pulsar keys rotate stored kid %q, which signs from %s", newKID, signsFrom.Format(time.RFC3339))

	// pulsar signs with the key from signsFrom, once each replica has
	// reloaded its keys, which it does once a minute.
	sleep(t, time.Until(signsFrom))
	deadline := time.Now().Add(90 * time.Second)
	after := signIn(t, identifier, api.ScopeRead)
	for keyID(t, after.AccessToken) != newKID {
		if time.Now().After(deadline) {
			t.Fatalf("pulsar still signs with kid %q, a minute and a half after %s", keyID(t, after.AccessToken), signsFrom.Format(time.RFC3339))
		}
		sleep(t, 5*time.Second)
		after = signIn(t, identifier, api.ScopeRead)
	}

	if _, err := cli.ListNotes(t.Context(), srv.URL, after.AccessToken); err != nil {
		t.Errorf("a token signed with the new key: cli.ListNotes() error = %v, want nil", err)
	}
	if _, err := cli.ListNotes(t.Context(), srv.URL, before.AccessToken); err != nil {
		t.Errorf("a token signed with the old key, after the rotation: cli.ListNotes() error = %v, want nil", err)
	}
}

// newAPI serves the API for the Resource Server registry.json registers,
// with its clock now, or the clock if now is nil.
func newAPI(t *testing.T, now func() time.Time) *httptest.Server {
	t.Helper()
	handler, err := api.New(t.Context(), api.Config{Issuer: issuer, Identifier: identifier, Now: now})
	if err != nil {
		t.Fatalf("api.New() error = %v, want nil", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// signIn runs the CLI's sign-in, for an access token for resource, or
// for UserInfo if resource is "", with scopes, and signs the End-User in
// and allows the request in a new browser.
func signIn(t *testing.T, resource string, scopes ...string) *cli.Session {
	t.Helper()
	b := newBrowser(t)
	session, err := cli.SignIn(t.Context(), cli.Config{
		Issuer: issuer, ClientID: clientID, Resource: resource, Scopes: scopes, OpenBrowser: b.open,
	})
	if err != nil {
		t.Fatalf("cli.SignIn() error = %v, want nil", err)
	}
	return session
}

// browser acts as the End-User's browser: it keeps cookies, follows
// redirects, and on pulsar's login page signs in, on its consent page
// allows the request, and on its logout page signs out. It records every
// response it receives.
type browser struct {
	client   *http.Client
	recorder *recorder
}

func newBrowser(t *testing.T) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v, want nil", err)
	}
	rec := &recorder{next: http.DefaultTransport}
	return &browser{client: &http.Client{Jar: jar, Transport: rec, Timeout: 30 * time.Second}, recorder: rec}
}

// page is a response the browser received, with its body read.
type page struct {
	url    *url.URL
	status int
	header http.Header
	body   string
}

// holds reports whether s appears in p's headers or body.
func (p page) holds(s string) bool {
	if strings.Contains(p.body, s) {
		return true
	}
	for _, values := range p.header {
		for _, v := range values {
			if strings.Contains(v, s) {
				return true
			}
		}
	}
	return false
}

// readBody reads resp's body, and puts back one that reads the same bytes,
// so that an http.RoundTripper can look at a response and pass it on.
func readBody(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

// recorder is an http.RoundTripper that records every response next
// returns, each redirect of one followed included.
type recorder struct {
	next http.RoundTripper

	mu    sync.Mutex
	pages []page
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	body, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pages = append(r.pages, page{url: req.URL, status: resp.StatusCode, header: resp.Header.Clone(), body: string(body)})
	return resp, nil
}

// received returns the responses recorded so far.
func (r *recorder) received() []page {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.pages)
}

// signInMu is held while a browser signs in, so that sign-ins happen one
// at a time: pulsar makes more than five logins at once as one End-User
// wait (docs/adr/0005-logins-throttled-per-end-user-by-delay.md).
var signInMu sync.Mutex

// The forms of pulsar's consent and logout pages, as a browser reads them.
var (
	formAction  = regexp.MustCompile(`<form method="post" action="([^"]*)">`)
	hiddenInput = regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)">`)
)

// The pages of pulsar's that visit answers, as it reports them.
const (
	loginPage   = "login"
	consentPage = "consent"
	logoutPage  = "logout"
)

// open opens url and answers each of pulsar's pages, until the browser
// reaches the redirect URI's page, which must answer 200.
func (b *browser) open(ctx context.Context, rawURL string) error {
	p, _, err := b.visit(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	if p.status != http.StatusOK {
		return fmt.Errorf("the redirect URI answered %d: %s", p.status, p.body)
	}
	return nil
}

// visit sends a request, a POST with form as its body, follows redirects,
// and answers each of pulsar's pages it is led to: on the login page it
// signs in, on the consent page it allows the request, and on the logout
// page it signs out. It returns the first page pulsar does not serve, and
// the pages of pulsar's it answered, in order.
func (b *browser) visit(ctx context.Context, method, rawURL string, form url.Values) (page, []string, error) {
	signInMu.Lock()
	defer signInMu.Unlock()

	pulsar, err := url.Parse(issuer)
	if err != nil {
		return page{}, nil, err
	}
	var answered []string
	p, err := send(ctx, b.client, method, rawURL, form)
	for range 4 {
		switch {
		case err != nil:
			return page{}, answered, err
		case p.url.Host != pulsar.Host:
			return p, answered, nil
		case strings.Contains(p.body, `name="password"`):
			// The login form posts to the page's own URL.
			answered = append(answered, loginPage)
			p, err = send(ctx, b.client, http.MethodPost, p.url.String(), url.Values{"username": {username}, "password": {password}})
		case strings.Contains(p.body, `name="decision" value="allow"`):
			answered = append(answered, consentPage)
			p, err = b.submit(ctx, p, "allow")
		case strings.Contains(p.body, `name="decision" value="logout"`):
			answered = append(answered, logoutPage)
			p, err = b.submit(ctx, p, "logout")
		default:
			return page{}, answered, fmt.Errorf("unexpected page at %s, status %d: %s", p.url, p.status, p.body)
		}
	}
	return page{}, answered, errors.New("the browser did not leave pulsar's pages")
}

// fetch sends a request, a POST with form as its body, and returns its
// response as it is: it follows no redirect, and answers no page.
func (b *browser) fetch(ctx context.Context, method, rawURL string, form url.Values) (page, error) {
	c := *b.client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return send(ctx, &c, method, rawURL, form)
}

// submit submits the form of p, one of pulsar's consent or logout pages,
// by its button for decision.
func (b *browser) submit(ctx context.Context, p page, decision string) (page, error) {
	m := formAction.FindStringSubmatch(p.body)
	if m == nil {
		return page{}, fmt.Errorf("the page at %s has no form", p.url)
	}
	action, err := p.url.Parse(html.UnescapeString(m[1]))
	if err != nil {
		return page{}, err
	}
	form := url.Values{"decision": {decision}}
	for _, h := range hiddenInput.FindAllStringSubmatch(p.body, -1) {
		form.Add(html.UnescapeString(h[1]), html.UnescapeString(h[2]))
	}
	return send(ctx, b.client, http.MethodPost, action.String(), form)
}

// send sends a request by client, a POST with form as its body, and
// returns the page it ends at, after the redirects client follows.
func send(ctx context.Context, client *http.Client, method, rawURL string, form url.Values) (page, error) {
	var body io.Reader = http.NoBody
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return page{}, err
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := client.Do(req)
	if err != nil {
		return page{}, err
	}
	defer resp.Body.Close() //nolint:errcheck // Read to its end; closing it reports nothing to act on.
	content, err := io.ReadAll(resp.Body)
	return page{url: resp.Request.URL, status: resp.StatusCode, header: resp.Header, body: string(content)}, err
}

// claims returns the claims of token, a JWS in compact serialization,
// unverified.
func claims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("%q is not a JWS in compact serialization", token)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("the claims of %q are not base64url: %v", token, err)
	}
	var c map[string]any
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("the claims of %q are not a JSON object: %v", token, err)
	}
	return c
}

// expiry returns token's exp.
func expiry(t *testing.T, token string) time.Time {
	t.Helper()
	exp, ok := claims(t, token)["exp"].(float64)
	if !ok {
		t.Fatalf("token %q has no exp", token)
	}
	return time.Unix(int64(exp), 0)
}

// withScope returns token with its scope claim replaced by scope, and its
// header and signature as they were.
func withScope(t *testing.T, token, scope string) string {
	t.Helper()
	c := claims(t, token)
	c["scope"] = scope
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("json.Marshal(claims) error = %v, want nil", err)
	}
	parts := strings.Split(token, ".")
	return parts[0] + "." + base64.RawURLEncoding.EncodeToString(b) + "." + parts[2]
}

// unsigned returns token's claims under the header {"alg": "none"}, with
// its typ and kid, and no signature.
func unsigned(t *testing.T, token string) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "none", "typ": "at+jwt", "kid": keyID(t, token)})
	if err != nil {
		t.Fatalf("json.Marshal(header) error = %v, want nil", err)
	}
	return base64.RawURLEncoding.EncodeToString(header) + "." + strings.Split(token, ".")[1] + "."
}

// keyID returns the kid of token, a JWT signed with RS256.
func keyID(t *testing.T, token string) string {
	t.Helper()
	jws, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("jose.ParseSignedCompact(%q) error = %v, want nil", token, err)
	}
	return jws.Signatures[0].Header.KeyID
}

// storedKey returns the kid and the start of signing of the key that
// `pulsar keys rotate` reports, in the JSON log line it writes.
func storedKey(t *testing.T, out []byte) (kid string, signsFrom time.Time) {
	t.Helper()
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		var line struct {
			Msg       string    `json:"msg"`
			KID       string    `json:"kid"`
			SignsFrom time.Time `json:"signs_from"`
		}
		if json.Unmarshal(sc.Bytes(), &line) == nil && line.Msg == "signing key stored" {
			return line.KID, line.SignsFrom
		}
	}
	t.Fatalf("pulsar keys rotate wrote no %q line: %s", "signing key stored", out)
	return "", time.Time{}
}

// sleep waits for d, or until the test ends.
func sleep(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case <-time.After(d):
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
}
