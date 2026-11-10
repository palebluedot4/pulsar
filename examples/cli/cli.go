// Package cli is an example native app: a public Client, with no secret,
// that signs the End-User in through their browser and a redirect to the
// loopback interface, as RFC 8252 describes, and calls the API example
// with the access token it gets for it.
package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Config is the CLI's registration with pulsar, and what it asks for.
type Config struct {
	// Issuer is pulsar's Issuer Identifier.
	Issuer string
	// ClientID is the CLI's client_id, registered with the loopback
	// redirect URI http://127.0.0.1/callback and no secret.
	ClientID string
	// Resource is the API's identifier, sent as the resource parameter
	// for an access token for the API (RFC 8707); with none, the access
	// token is for pulsar's UserInfo.
	Resource string
	// Scopes are the scopes asked for beside openid.
	Scopes []string
	// OpenBrowser opens the authorization request's URL in the End-User's
	// browser, where they sign in and allow the request.
	OpenBrowser func(ctx context.Context, url string) error
}

// Session is the outcome of a sign-in.
type Session struct {
	// AccessToken is for the API, or for UserInfo without Config.Resource.
	AccessToken string
	// IDToken is the ID token, verified.
	IDToken string
	// Subject is the End-User's sub, from the ID token.
	Subject string
}

// callbackPath is the path of the redirect URI.
const callbackPath = "/callback"

// SignIn signs the End-User in by the authorization code flow, with
// PKCE, state and nonce, and returns their Session. It waits until the
// browser comes back, or ctx is done.
func SignIn(ctx context.Context, cfg Config) (*Session, error) {
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover %s: %w", cfg.Issuer, err)
	}
	var meta struct {
		IssParameter bool `json:"authorization_response_iss_parameter_supported"`
	}
	if err := provider.Claims(&meta); err != nil {
		return nil, fmt.Errorf("discovery document of %s: %w", cfg.Issuer, err)
	}

	// A port the operating system chooses, on the loopback interface
	// alone, named by its IP literal rather than localhost (RFC 8252
	// §7.3, §8.3). pulsar accepts any port for the redirect URI the CLI
	// registered without one.
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen on the loopback interface: %w", err)
	}

	endpoint := provider.Endpoint()
	// A public Client has no secret to send, so it sends its client_id in
	// the token request's body (RFC 6749 §3.2.1), not by HTTP Basic.
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	oauthCfg := oauth2.Config{
		ClientID:    cfg.ClientID,
		Endpoint:    endpoint,
		RedirectURL: "http://" + ln.Addr().String() + callbackPath,
		Scopes:      append([]string{oidc.ScopeOpenID}, cfg.Scopes...),
	}

	// PKCE, which a public Client must use (RFC 9700 §2.1.1, RFC 8252
	// §8.1); state, against cross-site request forgery (RFC 6749
	// §10.12); and nonce, binding the ID token to this request (OpenID
	// Connect Core 1.0 §3.1.2.1).
	verifier := oauth2.GenerateVerifier()
	state, nonce := rand.Text(), rand.Text()
	resource := []oauth2.AuthCodeOption{}
	if cfg.Resource != "" {
		resource = append(resource, oauth2.SetAuthURLParam("resource", cfg.Resource))
	}
	authURL := oauthCfg.AuthCodeURL(state, append([]oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce)}, resource...)...)

	codes := make(chan result, 1)
	srv := &http.Server{
		Handler:           callbackHandler(cfg.Issuer, meta.IssParameter, state, codes),
		ReadHeaderTimeout: 10 * time.Second,
	}
	// Serve closes ln when it returns, once srv is shut down.
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		// Lets the page the browser is shown finish before the listener closes.
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	if err := cfg.OpenBrowser(ctx, authURL); err != nil {
		return nil, fmt.Errorf("open the browser: %w", err)
	}
	var code string
	select {
	case res := <-codes:
		if res.err != nil {
			return nil, res.err
		}
		code = res.code
	case <-ctx.Done():
		return nil, fmt.Errorf("wait for the browser: %w", ctx.Err())
	}

	// The same resource again, as RFC 8707 §2.2 allows at the token
	// endpoint.
	token, err := oauthCfg.Exchange(ctx, code, append([]oauth2.AuthCodeOption{oauth2.VerifierOption(verifier)}, resource...)...)
	if err != nil {
		return nil, fmt.Errorf("redeem the code: %w", err)
	}

	// The ID token is verified as OpenID Connect Core 1.0 §3.1.3.7 says:
	// its signature against pulsar's JWK Set, iss, aud, exp, and nonce.
	rawIDToken, _ := token.Extra("id_token").(string)
	idToken, err := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify the ID token: %w", err)
	}
	if idToken.Nonce != nonce {
		return nil, errors.New("the ID token's nonce is not the one sent")
	}
	return &Session{AccessToken: token.AccessToken, IDToken: rawIDToken, Subject: idToken.Subject}, nil
}

// result is what the browser brought back to the redirect URI.
type result struct {
	code string
	err  error
}

// callbackHandler returns the handler of the redirect URI. It sends the
// first response that carries state to codes, and answers the browser.
// A request without state, such as another page's, is refused and
// ignored.
func callbackHandler(issuer string, issParameter bool, state string, codes chan<- result) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+callbackPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("state") != state {
			http.Error(w, "This is not the response to the CLI's request.", http.StatusBadRequest)
			return
		}
		var res result
		switch {
		// The response comes from pulsar, and no other authorization
		// server: it names pulsar in iss, which pulsar's discovery
		// document says it always sends (RFC 9207 §2.4).
		case (issParameter || q.Has("iss")) && q.Get("iss") != issuer:
			res.err = fmt.Errorf("the authorization response's iss is %q, not %q", q.Get("iss"), issuer)
		case q.Has("error"):
			res.err = fmt.Errorf("authorization refused: %s: %s", q.Get("error"), q.Get("error_description"))
		case q.Get("code") == "":
			res.err = errors.New("the authorization response has no code")
		default:
			res.code = q.Get("code")
		}
		select {
		case codes <- res:
		default: // Already answered; this is a second response.
		}
		if res.err != nil {
			http.Error(w, "Sign-in failed; see the CLI.", http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, "Signed in. You can close this window and return to the CLI.\n")
	})
	return mux
}

// Note is a note, as the API sends and receives it.
type Note struct {
	Text string `json:"text"`
}

// ListNotes returns the End-User's notes from the API at apiURL.
func ListNotes(ctx context.Context, apiURL, accessToken string) ([]string, error) {
	var body struct {
		Notes []string `json:"notes"`
	}
	if err := call(ctx, http.MethodGet, apiURL+"/notes", accessToken, nil, http.StatusOK, &body); err != nil {
		return nil, err
	}
	return body.Notes, nil
}

// AddNote adds a note with text to the End-User's notes at the API at
// apiURL.
func AddNote(ctx context.Context, apiURL, accessToken, text string) error {
	b, err := json.Marshal(Note{Text: text})
	if err != nil {
		return err
	}
	return call(ctx, http.MethodPost, apiURL+"/notes", accessToken, b, http.StatusCreated, nil)
}

// StatusError is the error of a call the API answered with an unexpected
// status.
type StatusError struct {
	Status          int
	WWWAuthenticate string
}

func (e *StatusError) Error() string {
	if e.WWWAuthenticate != "" {
		return fmt.Sprintf("the API answered %d: %s", e.Status, e.WWWAuthenticate)
	}
	return fmt.Sprintf("the API answered %d", e.Status)
}

// call sends a request to the API with the access token in the
// Authorization header (RFC 6750 §2.1), and decodes the response's body
// into out, unless it is nil.
func call(ctx context.Context, method, url, accessToken string, body []byte, want int, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck // Closing a response body reports nothing to act on.
	if resp.StatusCode != want {
		return &StatusError{Status: resp.StatusCode, WWWAuthenticate: resp.Header.Get("WWW-Authenticate")}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
