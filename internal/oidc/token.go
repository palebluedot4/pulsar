package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/palebluedot4/pulsar/internal/oidc/internal/queries"
	"github.com/palebluedot4/pulsar/internal/registry"
)

// tokenParams are the parameters of a token request that pulsar reads.
// Every other parameter is ignored (RFC 6749 §3.2).
var tokenParams = []string{"grant_type", "code", "redirect_uri", "client_id", "client_secret"}

// Error codes of a token error response (RFC 6749 §5.2).
const (
	errInvalidClient        = "invalid_client"
	errInvalidGrant         = "invalid_grant"
	errUnsupportedGrantType = "unsupported_grant_type"
)

// tokenResponse is a successful token response (RFC 6749 §5.1, OpenID
// Connect Core 1.0 §3.1.3.3).
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	IDToken     string `json:"id_token"`
	// Always sent, since the scope granted may differ from the one
	// requested, which RFC 6749 §5.1 then requires.
	Scope string `json:"scope"`
}

// tokenError is a token error response (RFC 6749 §5.2).
type tokenError struct {
	status      int
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// HandleToken serves the token endpoint, by POST (RFC 6749 §3.2). It
// redeems an authorization code for an ID token and an access token, for
// a Client that authenticates with client_secret_basic.
func (p *Provider) HandleToken() http.Handler {
	return http.HandlerFunc(p.token)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	// Every response, success or error, is about a credential, and no
	// cache may keep it (RFC 6749 §5.1).
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")

	resp, tokErr := p.exchange(w, r)
	if tokErr != nil {
		if tokErr.status == http.StatusUnauthorized {
			// RFC 6749 §5.2: the scheme the Client used, or, if it used
			// none, the one pulsar supports.
			h.Set("WWW-Authenticate", `Basic realm="`+p.issuer.String()+`"`)
		}
		writeJSON(w, tokErr.status, tokErr)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// exchange reads a token request, authenticates its Client and exchanges
// its code for tokens.
func (p *Provider) exchange(w http.ResponseWriter, r *http.Request) (*tokenResponse, *tokenError) {
	// Parameters are read from the form-encoded body only (RFC 6749
	// §4.1.3).
	params, err := readParams(w, r)
	if err != nil {
		return nil, badRequest(errInvalidRequest, "The request body is not a form-encoded set of parameters.")
	}
	if name, ok := repeated(params, tokenParams); ok {
		return nil, badRequest(errInvalidRequest, "The parameter "+name+" is repeated.")
	}

	client, tokErr := p.authenticateClient(r, params)
	if tokErr != nil {
		return nil, tokErr
	}

	switch params.Get("grant_type") {
	case "authorization_code":
	case "":
		return nil, badRequest(errInvalidRequest, "The parameter grant_type is required.")
	default:
		return nil, badRequest(errUnsupportedGrantType, "Only the grant_type authorization_code is supported.")
	}
	code, redirectURI := params.Get("code"), params.Get("redirect_uri")
	switch {
	case code == "":
		return nil, badRequest(errInvalidRequest, "The parameter code is required.")
	case redirectURI == "":
		// Every authorization request pulsar accepts has a redirect_uri,
		// so every token request must repeat it (RFC 6749 §4.1.3).
		return nil, badRequest(errInvalidRequest, "The parameter redirect_uri is required.")
	}

	resp, err := p.issueTokens(r.Context(), client, code, redirectURI)
	switch {
	case errors.Is(err, errCodeNotRedeemable):
		return nil, badRequest(errInvalidGrant, "The code is invalid, expired, already used, or was issued to another client or redirect_uri.")
	case err != nil:
		p.logger.ErrorContext(r.Context(), "token endpoint", "error", err)
		return nil, &tokenError{status: http.StatusInternalServerError, Code: errServerError}
	}
	return resp, nil
}

// authenticateClient authenticates the Client of a token request by HTTP
// Basic authentication, with its client_id and secret each form-encoded
// before they are joined (RFC 6749 §2.3.1). A Client registered for
// another method fails, so that a weaker one cannot stand in for it.
func (p *Provider) authenticateClient(r *http.Request, params url.Values) (*registry.Client, *tokenError) {
	unauthorized := &tokenError{status: http.StatusUnauthorized, Code: errInvalidClient, Description: "Client authentication failed."}
	user, pass, ok := r.BasicAuth()
	if !ok {
		return nil, unauthorized
	}
	if params.Has("client_secret") {
		return nil, badRequest(errInvalidRequest, "The client must authenticate by one method only.")
	}
	id, errID := url.QueryUnescape(user)
	secret, errSecret := url.QueryUnescape(pass)
	if errID != nil || errSecret != nil {
		return nil, unauthorized
	}
	if bodyID := params.Get("client_id"); bodyID != "" && bodyID != id {
		return nil, badRequest(errInvalidRequest, "The client_id does not match the authenticated client.")
	}
	client, ok := p.registry.AuthenticateClientSecret(registry.ClientSecretBasic, id, secret)
	if !ok {
		return nil, unauthorized
	}
	return client, nil
}

// errCodeNotRedeemable is returned by issueTokens for a code that is
// unknown, expired, already redeemed, or issued to another Client or
// redirect URI.
var errCodeNotRedeemable = errors.New("the authorization code cannot be redeemed")

// issueTokens redeems code, for client and redirectURI, and returns the
// tokens issued for it. The code is redeemed and the access token recorded
// in one transaction, so that a code is redeemed at most once, and only
// when its token is recorded. The tokens are signed after it commits, so
// that the code's row is not locked meanwhile; signing fails only before
// the signing keys are loaded, when the endpoint is not served.
func (p *Provider) issueTokens(ctx context.Context, client *registry.Client, code, redirectURI string) (*tokenResponse, error) {
	now := time.Now()
	exp := now.Add(tokenLifetime)
	hash := hashCode(code)
	jti := rand.Text()
	var row queries.RedeemAuthorizationCodeRow
	// Read committed whatever the database's default, so that a second
	// redemption waits for the first and then finds the code redeemed,
	// rather than failing to serialize.
	err := pgx.BeginTxFunc(ctx, p.db, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		q := p.queries.WithTx(tx)
		var err error
		row, err = q.RedeemAuthorizationCode(ctx, queries.RedeemAuthorizationCodeParams{
			CodeHash:    hash,
			ClientID:    client.ID,
			RedirectUri: redirectURI,
			Now:         now,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			// TODO(#22): when the code was redeemed before, revoke the
			// access tokens issued from it.
			return errCodeNotRedeemable
		}
		if err != nil {
			return err
		}
		return q.InsertAccessToken(ctx, queries.InsertAccessTokenParams{Jti: jti, CodeHash: hash, Expiry: exp})
	})
	if err != nil {
		return nil, err
	}
	// Issuing a token is when expired ones are deleted. A failure leaves
	// them for the next and does not fail this one.
	if err := p.queries.DeleteExpiredAccessTokens(ctx, now); err != nil {
		p.logger.ErrorContext(ctx, "delete expired access tokens", "error", err)
	}

	scope := strings.Join(row.Scopes, " ")
	accessToken, err := p.keys.SignJWT("at+jwt", accessTokenClaims{
		Issuer:   p.issuer.String(),
		Expiry:   exp.Unix(),
		Audience: p.issuer.String(),
		Subject:  row.Subject,
		ClientID: client.ID,
		IssuedAt: now.Unix(),
		JTI:      jti,
		Scope:    scope,
	})
	if err != nil {
		return nil, err
	}
	idToken, err := p.keys.SignJWT("JWT", idTokenClaims{
		Issuer:          p.issuer.String(),
		Subject:         row.Subject,
		Audience:        client.ID,
		Expiry:          exp.Unix(),
		IssuedAt:        now.Unix(),
		AuthTime:        row.AuthTime.Unix(),
		Nonce:           row.Nonce,
		AccessTokenHash: accessTokenHash(accessToken),
	})
	if err != nil {
		return nil, err
	}
	return &tokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(tokenLifetime / time.Second),
		IDToken:     idToken,
		Scope:       scope,
	}, nil
}

// idTokenClaims are the claims of an ID token (OpenID Connect Core 1.0 §2,
// §3.1.3.6).
type idTokenClaims struct {
	Issuer          string `json:"iss"`
	Subject         string `json:"sub"`
	Audience        string `json:"aud"`
	Expiry          int64  `json:"exp"`
	IssuedAt        int64  `json:"iat"`
	AuthTime        int64  `json:"auth_time"`
	Nonce           string `json:"nonce,omitempty"`
	AccessTokenHash string `json:"at_hash"`
}

// accessTokenClaims are the claims of a JWT access token (RFC 9068 §2.2).
// Its audience is the issuer, the default resource of a request without a
// resource parameter (RFC 9068 §3).
type accessTokenClaims struct {
	Issuer   string `json:"iss"`
	Expiry   int64  `json:"exp"`
	Audience string `json:"aud"`
	Subject  string `json:"sub"`
	ClientID string `json:"client_id"`
	IssuedAt int64  `json:"iat"`
	JTI      string `json:"jti"`
	Scope    string `json:"scope"`
}

// accessTokenHash returns the at_hash of an access token signed with
// RS256: the left half of its SHA-256, base64url-encoded (OpenID Connect
// Core 1.0 §3.1.3.6).
func accessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

func badRequest(code, desc string) *tokenError {
	return &tokenError{status: http.StatusBadRequest, Code: code, Description: desc}
}

// writeJSON writes v as a JSON response with status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		// Only strings and integers are encoded, which always encode.
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body) // A failed write means the Client has gone.
}
