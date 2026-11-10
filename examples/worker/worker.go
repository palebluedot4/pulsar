// Package worker is an example machine Client: a job that calls the API
// example on its own behalf, with no End-User. It is a confidential Client
// registered for the client credentials grant alone (RFC 6749 §4.4). It
// gets its access tokens with golang.org/x/oauth2/clientcredentials, and
// authenticates with private_key_jwt (RFC 7523 §2.2): for each token
// request it signs a new client assertion with its private key, which
// never leaves it, as RFC 9700 §2.5 recommends.
package worker

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// Config is the worker's registration with pulsar, and what it asks for.
type Config struct {
	// Issuer is pulsar's Issuer Identifier.
	Issuer string
	// ClientID is the worker's client_id, registered for the client
	// credentials grant alone, with private_key_jwt.
	ClientID string
	// Key is the worker's private key, from ParseKey. pulsar's registry
	// lists its public key in the worker's jwks.
	Key *jose.JSONWebKey
	// Resource is the API's identifier, sent as the resource parameter.
	// pulsar requires one for this grant, and the access token is for it
	// alone (RFC 8707 §2).
	Resource string
	// Scopes are the scopes asked for, each one the worker is registered
	// for. pulsar requires at least one for this grant.
	Scopes []string
}

// jwtBearer is the client_assertion_type of a JWT that authenticates a
// Client (RFC 7523 §2.2).
const jwtBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" //nolint:gosec // G101: a URN that names a format, not a credential.

// assertionLifetime is how long a client assertion is valid. It is used
// at once, so a short life limits what one that leaked could do; pulsar
// refuses one used a second time before its exp in any case.
const assertionLifetime = time.Minute

// ParseKey parses data, a private key as a JWK (RFC 7517), with the alg it
// signs with and, if pulsar's registry gives one, its kid. The alg is one
// pulsar's registry accepts for a Client's key: ES256, with a P-256 key,
// or RS256 or PS256, with an RSA key.
func ParseKey(data []byte) (*jose.JSONWebKey, error) {
	var key jose.JSONWebKey
	if err := key.UnmarshalJSON(data); err != nil {
		return nil, fmt.Errorf("worker: the key is not a JWK: %w", err)
	}
	if !key.Valid() || key.IsPublic() {
		return nil, errors.New("worker: the key is not a private key")
	}
	// The key is of the type its alg takes, as pulsar's registry requires
	// of its public half.
	//
	//exhaustive:ignore
	switch alg := jose.SignatureAlgorithm(key.Algorithm); alg {
	case jose.ES256:
		if k, ok := key.Key.(*ecdsa.PrivateKey); !ok || k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("worker: alg %s takes a P-256 key", alg)
		}
	case jose.RS256, jose.PS256:
		if _, ok := key.Key.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("worker: alg %s takes an RSA key", alg)
		}
	default:
		return nil, fmt.Errorf("worker: the key's alg %q is not one of %s, %s or %s", alg, jose.ES256, jose.PS256, jose.RS256)
	}
	return &key, nil
}

// NewTokenSource discovers pulsar's token endpoint from its discovery
// document at cfg.Issuer, and returns a TokenSource whose every call to
// Token requests a new access token by the client credentials grant, with
// a new client assertion. Wrap it in oauth2.ReuseTokenSource to use each
// token until it expires, as cmd/worker does. ctx is used for discovery
// and for every token request, since oauth2.TokenSource's Token takes
// none, as with clientcredentials.Config's TokenSource: it bounds them.
func NewTokenSource(ctx context.Context, cfg Config) (oauth2.TokenSource, error) {
	if cfg.Key == nil {
		return nil, errors.New("worker: the key is required")
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("worker: discover %s: %w", cfg.Issuer, err)
	}
	// typ marks the JWT as a client assertion, so that it is not taken for
	// a JWT of another kind (RFC 10070 §4).
	opts := (&jose.SignerOptions{}).WithType("client-authentication+jwt")
	// Given the JWK, the signer names its kid in the header, so that pulsar
	// verifies with that key alone.
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(cfg.Key.Algorithm), Key: cfg.Key}, opts)
	if err != nil {
		return nil, fmt.Errorf("worker: %w", err)
	}
	return &tokenSource{ctx: ctx, cfg: cfg, tokenURL: provider.Endpoint().TokenURL, signer: signer}, nil
}

// tokenSource gets an access token by the client credentials grant, with
// a new client assertion, on each call to Token.
type tokenSource struct {
	ctx      context.Context //nolint:containedctx // oauth2.TokenSource's Token takes none, as clientcredentials' own source keeps its.
	cfg      Config
	tokenURL string
	signer   jose.Signer
}

func (s *tokenSource) Token() (*oauth2.Token, error) {
	assertion, err := s.assertion(time.Now())
	if err != nil {
		return nil, err
	}
	cc := clientcredentials.Config{
		ClientID: s.cfg.ClientID,
		TokenURL: s.tokenURL,
		Scopes:   s.cfg.Scopes,
		EndpointParams: url.Values{
			"resource":              {s.cfg.Resource},
			"client_assertion_type": {jwtBearer},
			"client_assertion":      {assertion},
		},
		// The client_id goes in the body beside the assertion (RFC 7521
		// §4.2), and no secret, since there is none. Left to auto-detect,
		// x/oauth2 would first send an empty secret by HTTP Basic beside
		// the assertion, which pulsar refuses as two methods at once (RFC
		// 7521 §4.2.1), and only then try again with the body alone.
		AuthStyle: oauth2.AuthStyleInParams,
	}
	tok, err := cc.Token(s.ctx)
	if err != nil {
		return nil, fmt.Errorf("worker: get an access token: %w", err)
	}
	return tok, nil
}

// assertion returns a new client assertion, valid from now, as RFC 7523 §3,
// RFC 10070 §4 and OpenID Connect Core 1.0 §9 require: iss and sub are the
// worker's client_id; aud is pulsar's issuer, and nothing else, rather
// than the token endpoint's URL, so that no other authorization server
// can replay it at pulsar (RFC 10070 §4); exp is a minute away; and jti is
// random, so that pulsar can refuse it if it is sent again.
func (s *tokenSource) assertion(now time.Time) (string, error) {
	claims := jwt.Claims{
		Issuer:   s.cfg.ClientID,
		Subject:  s.cfg.ClientID,
		Audience: jwt.Audience{s.cfg.Issuer},
		Expiry:   jwt.NewNumericDate(now.Add(assertionLifetime)),
		IssuedAt: jwt.NewNumericDate(now),
		ID:       rand.Text(),
	}
	raw, err := jwt.Signed(s.signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("worker: sign a client assertion: %w", err)
	}
	return raw, nil
}

// Run is one run of the job: it records a note with text in the API at
// apiURL, then returns the notes the API keeps for the worker. It calls
// the API with an access token from ts for each request; ts should reuse
// a token until it expires, as oauth2.ReuseTokenSource does, and then get
// a new one, since this grant issues no refresh token (RFC 6749 §4.4.3).
func Run(ctx context.Context, ts oauth2.TokenSource, apiURL, text string) ([]string, error) {
	// The client sends the access token in the Authorization header (RFC
	// 6750 §2.1).
	client := oauth2.NewClient(ctx, ts)

	b, err := json.Marshal(struct {
		Text string `json:"text"`
	}{text})
	if err != nil {
		return nil, fmt.Errorf("worker: %w", err)
	}
	if err := call(ctx, client, http.MethodPost, apiURL+"/notes", b, http.StatusCreated, nil); err != nil {
		return nil, fmt.Errorf("worker: record a note: %w", err)
	}
	var body struct {
		Notes []string `json:"notes"`
	}
	if err := call(ctx, client, http.MethodGet, apiURL+"/notes", nil, http.StatusOK, &body); err != nil {
		return nil, fmt.Errorf("worker: list its notes: %w", err)
	}
	return body.Notes, nil
}

// call sends a request to the API by client, and decodes the response's
// body into out, unless it is nil.
func call(ctx context.Context, client *http.Client, method, rawURL string, body []byte, want int, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck // Closing a response body reports nothing to act on.
	if resp.StatusCode != want {
		if c := resp.Header.Get("WWW-Authenticate"); c != "" {
			return fmt.Errorf("the API answered %d: %s", resp.StatusCode, c)
		}
		return fmt.Errorf("the API answered %d", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
