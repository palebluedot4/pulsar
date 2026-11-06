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
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/palebluedot4/pulsar/internal/login"
	"github.com/palebluedot4/pulsar/internal/oidc/internal/queries"
	"github.com/palebluedot4/pulsar/internal/registry"
)

// tokenParams are the parameters of a token request that pulsar reads.
// Every other parameter is ignored (RFC 6749 §3.2).
var tokenParams = []string{
	"grant_type", "code", "redirect_uri", "code_verifier", "refresh_token", "scope",
	"client_id", "client_secret", "client_assertion_type", "client_assertion",
}

// Error codes of a token error response (RFC 6749 §5.2), besides those
// the authorization endpoint shares.
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
	// Sent only for a code issued with offline access, from which a
	// Refresh Token Family starts (RFC 6749 §1.5).
	RefreshToken string `json:"refresh_token,omitempty"`
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
// a Client that authenticates with client_secret_basic, client_secret_post
// or private_key_jwt, whichever it registered, or for a public Client that
// sends its client_id. A code issued with a PKCE code challenge is
// redeemed only with its code_verifier (RFC 7636 §4.6). A code issued with
// offline access is redeemed for a refresh token too, and a refresh token
// for new tokens of each kind (RFC 6749 §6), with the same Client
// authentication.
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
// its grant for tokens.
func (p *Provider) exchange(w http.ResponseWriter, r *http.Request) (*tokenResponse, *tokenError) {
	// Parameters are read from the form-encoded body only (RFC 6749
	// §4.1.3, §6).
	params, err := readParams(w, r)
	if err != nil {
		return nil, badRequest(errInvalidRequest, "The request body is not a form-encoded set of parameters.")
	}
	if name, ok := repeated(params, tokenParams); ok {
		return nil, badRequest(errInvalidRequest, "The parameter "+name+" is repeated.")
	}

	// Each grant checks the request's form before its Client
	// authenticates, so that a malformed request does not use up a client
	// assertion, which authenticates once.
	switch params.Get("grant_type") {
	case "authorization_code":
		return p.exchangeCode(r, params)
	case "refresh_token":
		return p.exchangeRefreshToken(r, params)
	case "":
		return nil, badRequest(errInvalidRequest, "The parameter grant_type is required.")
	default:
		return nil, badRequest(errUnsupportedGrantType, "Only the grant_types authorization_code and refresh_token are supported.")
	}
}

// exchangeCode authenticates the Client of a token request for the
// authorization_code grant and exchanges its code for tokens.
func (p *Provider) exchangeCode(r *http.Request, params url.Values) (*tokenResponse, *tokenError) {
	code, redirectURI := params.Get("code"), params.Get("redirect_uri")
	switch {
	case code == "":
		return nil, badRequest(errInvalidRequest, "The parameter code is required.")
	case redirectURI == "":
		// Every authorization request pulsar accepts has a redirect_uri,
		// so every token request must repeat it (RFC 6749 §4.1.3).
		return nil, badRequest(errInvalidRequest, "The parameter redirect_uri is required.")
	}
	// A verifier of another form than RFC 7636 §4.1 gives is refused even
	// if its challenge matches, as Keycloak refuses it. It gets
	// invalid_grant, as a verifier that does not match does (§4.6).
	verifier := params.Get("code_verifier")
	if verifier != "" && !validPKCEValue(verifier) {
		return nil, badRequest(errInvalidGrant, "The code_verifier must be 43 to 128 unreserved characters.")
	}

	client, tokErr := p.authenticateClient(r, params)
	if tokErr != nil {
		return nil, tokErr
	}
	// The code challenge the verifier makes, which the code must have been
	// issued with; without a verifier, the code must have been issued
	// without one, so that a verifier cannot stand in for a challenge never
	// sent (RFC 9700 §2.1.1).
	var challenge string
	if verifier != "" {
		challenge = codeChallenge(verifier)
	} else if client.Public() {
		// A public Client always uses PKCE (ADR 0002), even for a code
		// issued without a challenge: before migration 00007, or by a
		// replica not yet upgraded to require one.
		return nil, badRequest(errInvalidRequest, "A public client must send code_verifier.")
	}
	resp, err := p.issueTokens(r.Context(), client, code, redirectURI, challenge)
	switch {
	case errors.Is(err, errCodeNotRedeemable):
		return nil, badRequest(errInvalidGrant, "The code is invalid, expired or already used, was issued to another client or redirect_uri, or does not match the code_verifier.")
	case err != nil:
		p.logger.ErrorContext(r.Context(), "token endpoint", "error", err)
		return nil, &tokenError{status: http.StatusInternalServerError, Code: errServerError}
	}
	return resp, nil
}

// authenticateClient authenticates the Client of a token request by the
// one method the request uses: client_secret_basic, client_secret_post or
// private_key_jwt; or, if it uses none, identifies a public Client by its
// client_id. A Client registered for another method fails, so that a
// weaker one cannot stand in for it.
func (p *Provider) authenticateClient(r *http.Request, params url.Values) (*registry.Client, *tokenError) {
	// An Authorization header of any scheme is an attempt to authenticate
	// by it, and an assertion parameter, even alone, one to authenticate by
	// an assertion.
	usesHeader := r.Header.Get("Authorization") != ""
	usesBody := params.Has("client_secret")
	usesAssertion := params.Has("client_assertion") || params.Has("client_assertion_type")
	switch {
	case usesAssertion && (usesHeader || usesBody):
		// RFC 7521 §4.2.1.
		return nil, unauthorized()
	case usesHeader && usesBody:
		// RFC 6749 §5.2.
		return nil, badRequest(errInvalidRequest, "The client must authenticate by one method only.")
	case usesHeader:
		return p.authenticateBasic(r, params)
	case usesBody:
		return p.authenticatePost(params)
	case usesAssertion:
		return p.authenticateAssertion(r.Context(), params)
	default:
		return p.identifyPublic(params)
	}
}

// identifyPublic identifies the public Client whose client_id is in the
// request body: one that has no credentials, and sends its client_id
// instead (RFC 6749 §3.2.1, §4.1.3). A Client registered for any other
// method fails, since it must authenticate (RFC 6749 §3.2.1), as does a
// request without client_id.
func (p *Provider) identifyPublic(params url.Values) (*registry.Client, *tokenError) {
	client, ok := p.registry.Client(params.Get("client_id"))
	if !ok || !client.Public() {
		return nil, unauthorized()
	}
	return client, nil
}

// unauthorized returns the answer to a token request whose Client fails
// to authenticate (RFC 6749 §5.2).
func unauthorized() *tokenError {
	return &tokenError{status: http.StatusUnauthorized, Code: errInvalidClient, Description: "Client authentication failed."}
}

// authenticatePost authenticates a Client registered for
// client_secret_post by the client_id and client_secret in the request
// body (RFC 6749 §2.3.1). The body is the only place parameters are read
// from, so the two are never taken from the request URI.
func (p *Provider) authenticatePost(params url.Values) (*registry.Client, *tokenError) {
	client, ok := p.registry.AuthenticateClientSecret(registry.ClientSecretPost, params.Get("client_id"), params.Get("client_secret"))
	if !ok {
		return nil, unauthorized()
	}
	return client, nil
}

// authenticateBasic authenticates a Client registered for
// client_secret_basic by HTTP Basic authentication, with its client_id and
// secret each form-encoded before they are joined (RFC 6749 §2.3.1).
func (p *Provider) authenticateBasic(r *http.Request, params url.Values) (*registry.Client, *tokenError) {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return nil, unauthorized()
	}
	id, errID := url.QueryUnescape(user)
	secret, errSecret := url.QueryUnescape(pass)
	if errID != nil || errSecret != nil {
		return nil, unauthorized()
	}
	if bodyID := params.Get("client_id"); bodyID != "" && bodyID != id {
		return nil, badRequest(errInvalidRequest, "The client_id does not match the authenticated client.")
	}
	client, ok := p.registry.AuthenticateClientSecret(registry.ClientSecretBasic, id, secret)
	if !ok {
		return nil, unauthorized()
	}
	return client, nil
}

// errCodeNotRedeemable is returned by issueTokens for a code that is
// unknown, expired, already redeemed, or issued to another Client or
// redirect URI or with another code challenge.
var errCodeNotRedeemable = errors.New("the authorization code cannot be redeemed")

// issueTokens redeems code, for client and redirectURI, and returns the
// tokens issued for it. The code must have been issued with challenge, the
// code challenge of the request's code_verifier, or "" if it sent none. A
// code_verifier that does not match uses up the code, so that only one
// verifier of the form RFC 7636 §4.1 allows can be tried against a code,
// and a weak one cannot be guessed in the code's lifetime.
//
// A code that was redeemed before, presented again, revokes the access
// tokens issued from it (RFC 6749 §4.1.2): their records are deleted, so
// that UserInfo refuses them. It does so only if the request is otherwise
// valid: client is the code's Client, which has authenticated by its
// registered method before this is called, redirectURI is the code's, and
// challenge is the code's. A replay with any other parameters revokes
// nothing, as OAuth 2.1 draft -17 §7.5.3 has it, so that one who has only
// seen a code cannot end the End-User's access with another Client
// (docs/research/refresh-tokens.md). The code's expiry is not checked: a
// valid replay after the code has expired revokes too, for as long as the
// code's record is kept.
//
// A code issued with offline access starts a Refresh Token Family, which
// ends familyLifetime after the code is redeemed, and is redeemed for the
// family's first refresh token too. The access token is recorded as the
// family's.
//
// The code is redeemed and the access token recorded in one transaction,
// with the family and its refresh token, if any, so that a code is
// redeemed at most once, and only when its tokens are recorded. The tokens
// are signed after it commits, so that the code's row is not locked
// meanwhile; signing fails only before the signing keys are loaded, when
// the endpoint is not served.
func (p *Provider) issueTokens(ctx context.Context, client *registry.Client, code, redirectURI, challenge string) (*tokenResponse, error) {
	now := time.Now()
	exp := now.Add(TokenLifetime)
	hash := hashCode(code)
	jti := rand.Text()
	var refreshToken string
	var row queries.RedeemAuthorizationCodeRow
	var claims claimsRequest
	// Whether the code is refused, after the transaction commits what the
	// refusal changed.
	var refused bool
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
			refused = true
			// A redemption of an expired code, or one whose Client or
			// redirect URI does not match, does not wait for one in
			// progress, so the code's row is locked first: it is then
			// read, and the tokens looked up, after any redemption in
			// progress has recorded its own.
			var stored queries.LockAuthorizationCodeRow
			stored, err = q.LockAuthorizationCode(ctx, hash)
			// A code no longer kept cannot show that the request's
			// parameters are its own, and one never redeemed has issued
			// no tokens: neither revokes anything, nor does a replay with
			// parameters other than the code's (OAuth 2.1 draft -17
			// §7.5.3).
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			if !stored.Redeemed || stored.ClientID != client.ID || stored.RedirectUri != redirectURI || stored.CodeChallenge != challenge {
				return nil
			}
			return q.DeleteAccessTokensOfCode(ctx, hash)
		}
		if err != nil {
			return err
		}
		// A verifier that does not match commits the code redeemed, with
		// no token issued from it (RFC 7636 §4.6).
		if row.CodeChallenge != challenge {
			refused = true
			return nil
		}
		// The token is recorded with the claims requested from UserInfo,
		// which UserInfo returns with those of its scopes.
		if claims, err = decodeClaimsRequest(row.Claims); err != nil {
			return err
		}
		userInfoClaims, err := claims.UserInfo.encode()
		if err != nil {
			return err
		}
		var familyID pgtype.Int8
		if slices.Contains(row.Scopes, login.OfflineAccess) {
			id, err := q.InsertRefreshTokenFamily(ctx, queries.InsertRefreshTokenFamilyParams{
				CodeHash: hash,
				ClientID: client.ID,
				Subject:  row.Subject,
				Scopes:   row.Scopes,
				Claims:   row.Claims,
				AuthTime: row.AuthTime,
				Expiry:   now.Add(familyLifetime),
			})
			if err != nil {
				return err
			}
			var refreshHash []byte
			refreshToken, refreshHash = newRefreshToken()
			if err := q.InsertRefreshToken(ctx, queries.InsertRefreshTokenParams{TokenHash: refreshHash, FamilyID: id}); err != nil {
				return err
			}
			familyID = pgtype.Int8{Int64: id, Valid: true}
		}
		return q.InsertAccessToken(ctx, queries.InsertAccessTokenParams{Jti: jti, CodeHash: hash, FamilyID: familyID, UserinfoClaims: userInfoClaims, Expiry: exp})
	})
	if err != nil {
		return nil, err
	}
	if refused {
		return nil, errCodeNotRedeemable
	}
	p.deleteExpiredAccessTokens(ctx, now)
	return p.signTokens(client, issued{
		subject:       row.Subject,
		scopes:        row.Scopes,
		authTime:      row.AuthTime,
		nonce:         row.Nonce,
		idTokenClaims: claims.IDToken,
		jti:           jti,
		refreshToken:  refreshToken,
	}, now)
}

// exchangeRefreshToken authenticates the Client of a token request for the
// refresh_token grant and exchanges its refresh token for tokens (RFC 6749
// §6).
func (p *Provider) exchangeRefreshToken(r *http.Request, params url.Values) (*tokenResponse, *tokenError) {
	refreshToken := params.Get("refresh_token")
	if refreshToken == "" {
		return nil, badRequest(errInvalidRequest, "The parameter refresh_token is required.")
	}
	// Each scope value adds an access range (RFC 6749 §3.3), so one given
	// twice is asked for once.
	var scopes []string
	for s := range strings.FieldsSeq(params.Get("scope")) {
		if !slices.Contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}

	client, tokErr := p.authenticateClient(r, params)
	if tokErr != nil {
		return nil, tokErr
	}
	resp, err := p.refresh(r.Context(), client, refreshToken, scopes)
	switch {
	case errors.Is(err, errRefreshTokenNotRedeemable):
		return nil, badRequest(errInvalidGrant, "The refresh token is invalid, expired, revoked or already used, or was issued to another client.")
	case errors.Is(err, errScopeNotGranted):
		return nil, badRequest(errInvalidScope, "The scope must not include any scope not originally granted.")
	case err != nil:
		p.logger.ErrorContext(r.Context(), "token endpoint", "error", err)
		return nil, &tokenError{status: http.StatusInternalServerError, Code: errServerError}
	}
	return resp, nil
}

// errRefreshTokenNotRedeemable is returned by refresh for a refresh token
// that is unknown or already used, or whose Refresh Token Family belongs to
// another Client, has ended or has been revoked.
var errRefreshTokenNotRedeemable = errors.New("the refresh token cannot be redeemed")

// errScopeNotGranted is returned by refresh for a scope that includes a
// value the Refresh Token Family was not granted.
var errScopeNotGranted = errors.New("the scope exceeds the scope granted")

// refresh redeems refreshToken, for client, and returns the tokens issued
// for it: an access token for scopes, or for the family's scopes if scopes
// is empty; an ID token; and the refresh token that replaces this one, in
// the same Refresh Token Family, for the family's scopes (RFC 6749 §6). A
// refresh token is redeemed once, so that a Client holds one at a time
// (RFC 9700 §4.14.2). Each token is the family's: the access token is
// recorded with the family and the code that started it, and the ID
// token's sub, aud and auth_time are those of the authorization the code
// was issued for (OpenID Connect Core 1.0 §12.2).
//
// The refresh token is redeemed, and its replacement and the access token
// recorded, in one transaction, so that of two redemptions of one refresh
// token, at most one succeeds. A scope that exceeds the family's rolls it
// back, so that the refresh token can still be redeemed. The tokens are
// signed after it commits, as issueTokens signs them.
func (p *Provider) refresh(ctx context.Context, client *registry.Client, refreshToken string, scopes []string) (*tokenResponse, error) {
	now := time.Now()
	jti := rand.Text()
	var row queries.RedeemRefreshTokenRow
	var claims claimsRequest
	var replacement string
	err := pgx.BeginTxFunc(ctx, p.db, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		q := p.queries.WithTx(tx)
		var err error
		row, err = q.RedeemRefreshToken(ctx, queries.RedeemRefreshTokenParams{
			TokenHash: hashCode(refreshToken),
			ClientID:  client.ID,
			Now:       now,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return errRefreshTokenNotRedeemable
		}
		if err != nil {
			return err
		}
		if len(scopes) == 0 {
			scopes = row.Scopes
		} else if !isSubset(scopes, row.Scopes) {
			return errScopeNotGranted
		}
		if claims, err = decodeClaimsRequest(row.Claims); err != nil {
			return err
		}
		userInfoClaims, err := claims.UserInfo.encode()
		if err != nil {
			return err
		}
		var replacementHash []byte
		replacement, replacementHash = newRefreshToken()
		if err := q.InsertRefreshToken(ctx, queries.InsertRefreshTokenParams{TokenHash: replacementHash, FamilyID: row.ID}); err != nil {
			return err
		}
		return q.InsertAccessToken(ctx, queries.InsertAccessTokenParams{
			Jti:            jti,
			CodeHash:       row.CodeHash,
			FamilyID:       pgtype.Int8{Int64: row.ID, Valid: true},
			UserinfoClaims: userInfoClaims,
			Expiry:         now.Add(TokenLifetime),
		})
	})
	if err != nil {
		return nil, err
	}
	p.deleteExpiredAccessTokens(ctx, now)
	// The ID token has no nonce, which §12.2 allows only with the value
	// of the original, and recommends against.
	return p.signTokens(client, issued{
		subject:       row.Subject,
		scopes:        scopes,
		authTime:      row.AuthTime,
		idTokenClaims: claims.IDToken,
		jti:           jti,
		refreshToken:  replacement,
	}, now)
}

// isSubset reports whether every value of sub is one of set.
func isSubset(sub, set []string) bool {
	for _, v := range sub {
		if !slices.Contains(set, v) {
			return false
		}
	}
	return true
}

// deleteExpiredAccessTokens deletes the records of access tokens expired
// at now. Issuing a token is when they are deleted. A failure leaves them
// for the next and does not fail this one.
func (p *Provider) deleteExpiredAccessTokens(ctx context.Context, now time.Time) {
	if err := p.queries.DeleteExpiredAccessTokens(ctx, now); err != nil {
		p.logger.ErrorContext(ctx, "delete expired access tokens", "error", err)
	}
}

// issued is what a token response is issued for, and the tokens recorded
// for it that signTokens does not sign.
type issued struct {
	subject string
	// scopes are those of the access token.
	scopes   []string
	authTime time.Time
	// nonce is the ID token's, or "" for none.
	nonce string
	// idTokenClaims are the claims the claims parameter requested in the ID
	// token.
	idTokenClaims requestedClaims
	// jti is the access token's, as it is recorded.
	jti string
	// refreshToken is the refresh token issued, or "" for none.
	refreshToken string
}

// signTokens returns the token response for t, issued to client at now:
// an access token and an ID token, each valid for TokenLifetime, and t's
// refresh token, if any.
func (p *Provider) signTokens(client *registry.Client, t issued, now time.Time) (*tokenResponse, error) {
	exp := now.Add(TokenLifetime)
	scope := strings.Join(t.scopes, " ")
	accessToken, err := p.keys.SignJWT("at+jwt", accessTokenClaims{
		Issuer:   p.issuer.String(),
		Expiry:   exp.Unix(),
		Audience: p.issuer.String(),
		Subject:  t.subject,
		ClientID: client.ID,
		IssuedAt: now.Unix(),
		JTI:      t.jti,
		Scope:    scope,
	})
	if err != nil {
		return nil, err
	}
	// The claims of an ID token (OpenID Connect Core 1.0 §2, §3.1.3.6),
	// and those the claims parameter requests in it (§5.5), which are
	// Standard Claims other than sub and so never one of them. The claims
	// of the scopes granted are not among them: they are returned from
	// UserInfo, since an access token is issued (§5.4).
	idClaims := map[string]any{
		"iss":       p.issuer.String(),
		"sub":       t.subject,
		"aud":       client.ID,
		"exp":       exp.Unix(),
		"iat":       now.Unix(),
		"auth_time": t.authTime.Unix(),
		"at_hash":   accessTokenHash(accessToken),
	}
	if t.nonce != "" {
		idClaims["nonce"] = t.nonce
	}
	// An End-User removed from the registry since the code was issued has
	// no claims to release, and no error follows from that (§5.5.1).
	if u, ok := p.registry.EndUser(t.subject); ok && len(t.idTokenClaims) > 0 {
		all, err := endUserClaims(u)
		if err != nil {
			return nil, err
		}
		t.idTokenClaims.release(idClaims, all)
	}
	idToken, err := p.keys.SignJWT("JWT", idClaims)
	if err != nil {
		return nil, err
	}
	return &tokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(TokenLifetime / time.Second),
		IDToken:      idToken,
		RefreshToken: t.refreshToken,
		Scope:        scope,
	}, nil
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
		// Only strings, numbers, booleans, and maps and slices of them
		// are encoded, which always encode.
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body) // A failed write means the Client has gone.
}
