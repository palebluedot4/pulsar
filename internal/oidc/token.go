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
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/palebluedot4/pulsar/internal/login"
	"github.com/palebluedot4/pulsar/internal/oidc/internal/queries"
	"github.com/palebluedot4/pulsar/internal/registry"
)

// tokenParams are the parameters of a token request that pulsar reads,
// besides resource, which RFC 8707 §2 lets a Client repeat, and which is
// checked apart, with its own error code (resourceOnce). Every other
// parameter is ignored (RFC 6749 §3.2).
var tokenParams = []string{
	"grant_type", "code", "redirect_uri", "code_verifier", "refresh_token", "scope",
	"client_id", "client_secret", "client_assertion_type", "client_assertion",
}

// Error codes of a token error response (RFC 6749 §5.2), besides those
// the authorization endpoint shares.
const (
	errInvalidClient        = "invalid_client"
	errInvalidGrant         = "invalid_grant"
	errUnauthorizedClient   = "unauthorized_client"
	errUnsupportedGrantType = "unsupported_grant_type"
)

// tokenResponse is a successful token response (RFC 6749 §5.1, OpenID
// Connect Core 1.0 §3.1.3.3).
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	// Sent for every grant but client_credentials, which has no End-User
	// for an ID token to be about (OpenID Connect Core 1.0 §2).
	IDToken string `json:"id_token,omitempty"`
	// Sent for a code issued with offline access, from which a Refresh
	// Token Family starts (RFC 6749 §1.5), and for every refresh token of
	// the family redeemed, replacing it.
	RefreshToken string `json:"refresh_token,omitempty"`
	// Always sent, since the scope granted may differ from the one
	// requested, which RFC 6749 §5.1 then requires.
	Scope string `json:"scope"`
}

// tokenError is a token error response (RFC 6749 §5.2).
type tokenError struct {
	status      int
	retryAfter  time.Duration // sent as Retry-After, if not 0
	Code        string        `json:"error"`
	Description string        `json:"error_description,omitempty"`
}

// HandleToken serves the token endpoint, by POST (RFC 6749 §3.2). It
// redeems an authorization code for an ID token and an access token, for
// a Client that authenticates with client_secret_basic, client_secret_post
// or private_key_jwt, whichever it registered, or for a public Client that
// sends its client_id. A code issued with a PKCE code challenge is
// redeemed only with its code_verifier (RFC 7636 §4.6). A code issued with
// offline access is redeemed for a refresh token too, and a refresh token
// for new tokens of each kind (RFC 6749 §6), with the same Client
// authentication. A machine Client, one registered for client_credentials
// alone, gets an access token of its own for a Resource Server (RFC 6749
// §4.4). Each grant is refused with unauthorized_client to a Client not
// registered for it. A public Client running in a browser may send its
// requests from the origin of one of its redirect URIs (corsPolicy).
func (p *Provider) HandleToken() http.Handler {
	return http.HandlerFunc(p.token)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	setCredentialHeaders(w)
	r = withEndpoint(r, "token endpoint")
	resp, tokErr := p.exchange(w, r)
	if tokErr != nil {
		p.writeTokenError(w, tokErr)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// setCredentialHeaders sets the headers of every response of the token
// and revocation endpoints. Each, success or error, is about a credential,
// and no cache may keep it (RFC 6749 §5.1); each varies by origin
// (corsPolicy.check).
func setCredentialHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	h.Add("Vary", "Origin")
}

// writeTokenError writes tokErr as an error response in the JSON form of
// RFC 6749 §5.2.
func (p *Provider) writeTokenError(w http.ResponseWriter, tokErr *tokenError) {
	h := w.Header()
	if tokErr.status == http.StatusUnauthorized {
		// RFC 6749 §5.2: the scheme the Client used, or, if it used
		// none, the one pulsar supports.
		h.Set("WWW-Authenticate", `Basic realm="`+p.issuer.String()+`"`)
	}
	if tokErr.retryAfter > 0 {
		h.Set("Retry-After", strconv.Itoa(int(tokErr.retryAfter/time.Second)))
	}
	writeJSON(w, tokErr.status, tokErr)
}

// exchange reads a token request, authenticates its Client and exchanges
// its grant for tokens.
func (p *Provider) exchange(w http.ResponseWriter, r *http.Request) (*tokenResponse, *tokenError) {
	params, tokErr := p.readClientRequest(w, r, tokenParams)
	if tokErr != nil {
		return nil, tokErr
	}

	// Each grant checks the request's form before its Client
	// authenticates, so that a malformed request does not use up a client
	// assertion, which authenticates once.
	switch registry.GrantType(params.Get("grant_type")) {
	case registry.AuthorizationCode:
		return p.exchangeCode(r, params)
	case registry.RefreshToken:
		return p.exchangeRefreshToken(r, params)
	case registry.ClientCredentials:
		return p.exchangeClientCredentials(r, params)
	case "":
		return nil, badRequest(errInvalidRequest, "The parameter grant_type is required.")
	default:
		return nil, badRequest(errUnsupportedGrantType, "Only the grant_types authorization_code, refresh_token and client_credentials are supported.")
	}
}

// authenticateFor authenticates the Client of a token request for grant,
// as authenticateClient does, and refuses one not registered for grant
// (RFC 6749 §5.2), a public Client included.
func (p *Provider) authenticateFor(r *http.Request, params url.Values, grant registry.GrantType) (*registry.Client, *tokenError) {
	client, tokErr := p.authenticateClient(r, params)
	if tokErr != nil {
		return nil, tokErr
	}
	if !client.AllowsGrant(grant) {
		return nil, badRequest(errUnauthorizedClient, "The client is not registered for the grant_type "+string(grant)+".")
	}
	return client, nil
}

// readClientRequest returns the parameters of r, a request to the token or
// revocation endpoint, read from its form-encoded body only (RFC 6749
// §4.1.3, §6; RFC 7009 §2.1), none of names repeated. A request from a
// browser is checked against the public Client its client_id names before
// the request does anything, since a browser sends it without a
// preflight: one from an origin not allowed must not redeem a code,
// rotate a refresh token or revoke a token when the browser withholds the
// response (RFC 10017 §6.3.3.4).
func (p *Provider) readClientRequest(w http.ResponseWriter, r *http.Request, names []string) (url.Values, *tokenError) {
	params, err := readParams(w, r)
	if err != nil {
		return nil, badRequest(errInvalidRequest, "The request body is not a form-encoded set of parameters.")
	}
	if name, ok := repeated(params, names); ok {
		return nil, badRequest(errInvalidRequest, "The parameter "+name+" is repeated.")
	}
	named, _ := p.registry.Client(params.Get("client_id"))
	if !p.tokenCORS.check(w, r, named) {
		return nil, badRequest(errInvalidRequest, p.tokenCORS.refusal)
	}
	return params, nil
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
	if tokErr := resourceOnce(params); tokErr != nil {
		return nil, tokErr
	}

	client, tokErr := p.authenticateFor(r, params, registry.AuthorizationCode)
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
	resp, err := p.issueTokens(r.Context(), client, code, redirectURI, challenge, params.Get("resource"))
	switch {
	case errors.Is(err, errCodeNotRedeemable):
		return nil, badRequest(errInvalidGrant, "The code is invalid, expired or already used, was issued to another client or redirect_uri, does not match the code_verifier, or is for an End-User who no longer exists.")
	case errors.Is(err, errResourceNotGranted):
		return nil, badRequest(errInvalidTarget, resourceNotGranted)
	case err != nil:
		return nil, p.serverError(r.Context(), err)
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
		return p.authenticatePost(r.Context(), params)
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

// endpointKey is the key under which a request's context holds the name of
// the endpoint serving it, by which serverError logs its failures.
type endpointKey struct{}

// withEndpoint returns r with name, that of the endpoint serving it, in its
// context, so that a failure in code the token and revocation endpoints
// share is logged as the right one's.
func withEndpoint(r *http.Request, name string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), endpointKey{}, name))
}

// serverError logs err, which ends a request to the token or revocation
// endpoint for a reason of pulsar's own, under the name of the endpoint
// ctx holds (withEndpoint), and returns the answer to the request.
func (p *Provider) serverError(ctx context.Context, err error) *tokenError {
	name, _ := ctx.Value(endpointKey{}).(string)
	p.logger.ErrorContext(ctx, name, "error", err)
	return &tokenError{status: http.StatusInternalServerError, Code: errServerError}
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
func (p *Provider) authenticatePost(ctx context.Context, params url.Values) (*registry.Client, *tokenError) {
	return p.authenticateSecret(ctx, registry.ClientSecretPost, params.Get("client_id"), params.Get("client_secret"))
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
	return p.authenticateSecret(r.Context(), registry.ClientSecretBasic, id, secret)
}

// authenticateSecret authenticates the Client whose client_id and secret
// these are, if it registered method. The README requires a Client
// secret of at least 256 random bits, so that guessing cannot find one, as
// RFC 6749 §10.10 and RFC 6819 §5.1.4.2.2 have it, and its attempts are
// not counted, as an End-User's are: a count would let anyone who knows a
// client_id, which is public, hold up that Client's token requests (docs/adr/0005-logins-throttled-per-end-user-by-delay.md).
//
// No error code of RFC 6749 §5.2 is for a request refused for want of
// capacity to check its secret, so it gets temporarily_unavailable, which
// §4.1.2.1 defines for the authorization endpoint.
func (p *Provider) authenticateSecret(ctx context.Context, method registry.AuthMethod, id, secret string) (*registry.Client, *tokenError) {
	client, ok, err := p.registry.AuthenticateClientSecret(ctx, method, id, secret)
	switch {
	case errors.Is(err, registry.ErrBusy):
		// Too many logins and token requests at once on this replica
		// (RFC 9110 §15.6.4).
		return nil, &tokenError{
			status:      http.StatusServiceUnavailable,
			retryAfter:  time.Second,
			Code:        errTemporarilyUnavailable,
			Description: "The server is too busy to authenticate the client.",
		}
	case err != nil:
		return nil, p.serverError(ctx, err)
	case !ok:
		return nil, unauthorized()
	}
	return client, nil
}

// errCodeNotRedeemable is returned by issueTokens for a code that is
// unknown, expired, already redeemed, or issued to another Client or
// redirect URI or with another code challenge, or for an End-User no
// longer in the registry.
var errCodeNotRedeemable = errors.New("the authorization code cannot be redeemed")

// resourceOnce refuses a token request that sends resource more than
// once, as the authorization endpoint does (parseResource). Each grant
// calls it once its other parameters are known to be well formed, so that
// a request missing one is told so first.
func resourceOnce(params url.Values) *tokenError {
	if len(params["resource"]) > 1 {
		return badRequest(errInvalidTarget, "The resource must be sent once.")
	}
	return nil
}

// errResourceNotGranted is returned by issueTokens and refresh for a token
// request whose resource grantedResource refuses. resourceNotGranted
// describes it to the Client.
var errResourceNotGranted = errors.New("the resource is not the one granted")

const resourceNotGranted = "The resource is not the one the code or refresh token was issued for, the client may no longer request its Resource Server, or the scope holds none of its scopes."

// grantedResource returns the Resource Server whose identifier is granted,
// that of a code or Refresh Token Family, or nil if it is "", for a token
// request by client with the resource parameter requested, "" if it sent
// none, for an access token for scopes. It reports false if requested
// names another Resource Server, or none was granted (RFC 8707 §2.2); if
// client may no longer request that Resource Server; or if scopes hold
// none of its scopes, an invalid combination of resource and scope (§2),
// as a refresh for a narrower scope may ask for, or a Resource Server's
// scopes changed in the registry may leave.
func (p *Provider) grantedResource(client *registry.Client, granted, requested string, scopes []string) (*registry.ResourceServer, bool) {
	switch {
	case requested != "" && requested != granted:
		return nil, false
	case granted == "":
		return nil, true
	}
	s, ok := p.registry.ResourceServer(client, granted)
	if !ok || !slices.ContainsFunc(scopes, s.HasScope) {
		return nil, false
	}
	return s, true
}

// issueTokens redeems code, for client and redirectURI, and returns the
// tokens issued for it. The code must have been issued with challenge, the
// code challenge of the request's code_verifier, or "" if it sent none. A
// code_verifier that does not match uses up the code, so that only one
// verifier of the form RFC 7636 §4.1 allows can be tried against a code,
// and a weak one cannot be guessed in the code's lifetime.
//
// The access token is for the Resource Server the code was issued for, if
// any, which resource, the request's resource parameter, must name if it is
// not "" (grantedResource). A resource refused leaves the code to be
// redeemed, as RFC 8707 does not say that it uses the code up.
//
// A code that was redeemed before, presented again, revokes the tokens
// issued from it (RFC 6749 §4.1.2): the Refresh Token Family it started,
// if any, and the access tokens issued from it, directly or in the family,
// whose records are deleted, so that UserInfo refuses them. It does so
// only if the request is otherwise valid: client is the code's Client,
// which has authenticated by its registered method before this is called,
// redirectURI is the code's, and challenge is the code's. A replay with
// any other parameters revokes nothing, as OAuth 2.1 draft -17 §7.5.3 has
// it, so that one who has only seen a code cannot end the End-User's
// access with another Client (docs/research/refresh-tokens.md). The code's
// expiry is not checked: a valid replay after the code has expired revokes
// too, for as long as the code's record is kept: until its access token
// expires, or while its family lives, and not once its tokens are revoked.
//
// A code issued with offline access starts a Refresh Token Family, which
// ends familyLifetime after the code is redeemed, and is redeemed for the
// family's first refresh token too. Every access token of the family,
// this one included, is recorded with the code's hash, by which revoking
// the family finds them.
//
// The code is redeemed and the access token recorded in one transaction,
// with the family and its refresh token, if any, so that a code is
// redeemed at most once, and only when its tokens are recorded. The tokens
// are signed after it commits, so that the code's row is not locked
// meanwhile; signing fails only before the signing keys are loaded, when
// the endpoint is not served.
func (p *Provider) issueTokens(ctx context.Context, client *registry.Client, code, redirectURI, challenge, resource string) (*tokenResponse, error) {
	now := time.Now()
	exp := now.Add(TokenLifetime)
	hash := hashCode(code)
	jti := rand.Text()
	var refreshToken string
	var row queries.RedeemAuthorizationCodeRow
	var claims claimsRequest
	var server *registry.ResourceServer
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
			CodeHash:          hash,
			ClientID:          client.ID,
			RedirectUri:       redirectURI,
			Now:               now,
			AccessTokenExpiry: exp,
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
			if err := revokeCode(ctx, q, hash); err != nil {
				return err
			}
			// The transaction holds the code's row already, so it need not
			// wait as a refresh would (stopKeepingCode).
			return q.StopKeepingAuthorizationCode(ctx, queries.StopKeepingAuthorizationCodeParams{CodeHash: hash, Now: now})
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
		// A code whose End-User has been removed from the registry is
		// refused, as a refresh token is, and is not used up: refusing rolls
		// back marking it redeemed, so it is redeemed if they are back
		// within its lifetime. That comes before the resource, as in a
		// refresh, since no resource would do.
		if _, ok := p.registry.EndUser(row.Subject); !ok {
			return errCodeNotRedeemable
		}
		// Refusing rolls back marking the code redeemed.
		var granted bool
		if server, granted = p.grantedResource(client, row.Resource, resource, row.Scopes); !granted {
			return errResourceNotGranted
		}
		var userInfoClaims []byte
		if claims, userInfoClaims, err = decodeStoredClaims(row.Claims); err != nil {
			return err
		}
		if slices.Contains(row.Scopes, login.OfflineAccess) {
			id, err := q.InsertRefreshTokenFamily(ctx, queries.InsertRefreshTokenFamilyParams{
				CodeHash: hash,
				ClientID: client.ID,
				Subject:  row.Subject,
				Scopes:   row.Scopes,
				Claims:   row.Claims,
				Resource: row.Resource,
				AuthTime: row.AuthTime,
				Expiry:   now.Add(familyLifetime),
			})
			if err != nil {
				return err
			}
			if refreshToken, err = insertRefreshToken(ctx, q, id); err != nil {
				return err
			}
		}
		return q.InsertAccessToken(ctx, queries.InsertAccessTokenParams{Jti: jti, CodeHash: hash, UserinfoClaims: userInfoClaims, Expiry: exp})
	})
	if err != nil {
		return nil, err
	}
	if refused {
		return nil, errCodeNotRedeemable
	}
	return p.signTokens(client, issuance{
		subject:       row.Subject,
		resource:      server,
		scopes:        row.Scopes,
		expiry:        exp,
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
	if tokErr := resourceOnce(params); tokErr != nil {
		return nil, tokErr
	}
	scopes := requestedScopes(params)

	client, tokErr := p.authenticateFor(r, params, registry.RefreshToken)
	if tokErr != nil {
		return nil, tokErr
	}
	resp, err := p.refresh(r.Context(), client, refreshToken, scopes, params.Get("resource"))
	switch {
	case errors.Is(err, errRefreshTokenNotRedeemable):
		return nil, badRequest(errInvalidGrant, "The refresh token is invalid, expired, revoked or already used, was issued to another client, or is for an End-User who no longer exists.")
	case errors.Is(err, errScopeNotGranted):
		return nil, badRequest(errInvalidScope, "The scope must not include any scope not originally granted.")
	case errors.Is(err, errResourceNotGranted):
		return nil, badRequest(errInvalidTarget, resourceNotGranted)
	case err != nil:
		return nil, p.serverError(r.Context(), err)
	}
	return resp, nil
}

// requestedScopes returns the values of a token request's scope, in the
// order sent. Each scope value adds an access range (RFC 6749 §3.3), so
// one given twice is asked for once.
func requestedScopes(params url.Values) []string {
	var scopes []string
	for s := range strings.FieldsSeq(params.Get("scope")) {
		if !slices.Contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}
	return scopes
}

// exchangeClientCredentials authenticates the Client of a token request
// for the client_credentials grant and issues it an access token of its
// own (RFC 6749 §4.4), for the one Resource Server its resource names and
// for scopes of that Resource Server it is registered for. Neither has a
// default: a request without resource gets invalid_target (RFC 8707 §2),
// and one without scope invalid_scope (RFC 6749 §3.3), so that a Client
// gets only the access it asks for (RFC 9700 §2.3), as an authorization
// request with resource does.
//
// The form is checked before the Client authenticates, as for the other
// grants; then, in turn, that the Client is registered for the grant, the
// resource, and the scope. A scope the Client is not registered for, openid
// included, gets invalid_scope; one it is registered for, of another
// Resource Server than resource names, invalid_target, an invalid
// combination of resource and scope (RFC 8707 §2).
func (p *Provider) exchangeClientCredentials(r *http.Request, params url.Values) (*tokenResponse, *tokenError) {
	if tokErr := resourceOnce(params); tokErr != nil {
		return nil, tokErr
	}
	resource := params.Get("resource")
	if resource == "" {
		return nil, badRequest(errInvalidTarget, "The parameter resource is required.")
	}
	scopes := requestedScopes(params)
	if len(scopes) == 0 {
		return nil, badRequest(errInvalidScope, "The parameter scope is required.")
	}

	client, tokErr := p.authenticateFor(r, params, registry.ClientCredentials)
	if tokErr != nil {
		return nil, tokErr
	}
	server, ok := p.registry.ResourceServer(client, resource)
	switch {
	case !ok:
		return nil, badRequest(errInvalidTarget, "The resource must be one Resource Server registered for this client, named by its identifier.")
	case !isSubset(scopes, client.Scopes):
		return nil, badRequest(errInvalidScope, "The scope must include only scopes registered for this client.")
	case slices.ContainsFunc(scopes, func(s string) bool { return !server.HasScope(s) }):
		return nil, badRequest(errInvalidTarget, "The scope must include only scopes of the Resource Server the resource names.")
	}
	return p.issueClientToken(r.Context(), client, server, scopes)
}

// issueClientToken returns the token response to a machine Client's
// request for an access token for server and scopes: an access token
// whose sub is the Client's client_id, as RFC 9068 §2.2 says it SHOULD be
// for this grant, and which the registry keeps from equaling any End-User's
// Subject (docs/adr/0007-a-machine-clients-sub-is-its-client-id.md). It
// carries no refresh token (RFC 6749 §4.4.3) and no ID token, since there
// is no End-User. The access token is not recorded: none is looked up at
// UserInfo, which refuses it for its aud, or at the revocation endpoint,
// which answers it as any access token for a Resource Server, with 200 and
// nothing revoked, so it lives until it expires, as RFC 7009 §3 has a
// self-contained token do.
func (p *Provider) issueClientToken(ctx context.Context, client *registry.Client, server *registry.ResourceServer, scopes []string) (*tokenResponse, *tokenError) {
	now := time.Now()
	exp := now.Add(TokenLifetime)
	accessToken, err := p.signAccessToken(client.ID, client.ID, server.Identifier, scopes, rand.Text(), now, exp)
	if err != nil {
		return nil, p.serverError(ctx, err)
	}
	return &tokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(exp.Sub(now) / time.Second),
		Scope:       strings.Join(scopes, " "),
	}, nil
}

// errRefreshTokenNotRedeemable is returned by refresh for a refresh token
// that is unknown or already used, or whose Refresh Token Family belongs to
// another Client, has ended or has been revoked, or is for an End-User no
// longer in the registry.
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
// recorded with the code that started it, and the ID token's sub, aud and
// auth_time are those of the authorization the code was issued for (OpenID
// Connect Core 1.0 §12.2). A refresh token whose End-User has been removed
// from the registry is refused; one whose Client has been removed never
// gets here, since the Client cannot authenticate. The access token is for
// the family's Resource Server, if any, which resource must name if it is
// not "" (grantedResource), as RFC 8707 §2.1 applies the resource to the
// "full authorization grant".
//
// A refresh token already used, presented again by its own Client while
// its family lives, shows that it was stolen, and from whom pulsar cannot
// tell, so the whole family is revoked: its refresh tokens are refused
// from then on, and the records of its access tokens, the one issued from
// the code included, are deleted, so that UserInfo refuses them (RFC 9700
// §4.14.2). There is no grace period, not even for a Client retrying a
// refresh whose response it never received. A refresh token presented by
// another Client revokes nothing, as a code replayed by another Client
// does not (OAuth 2.1 draft -17 §7.5.3), and as most providers surveyed
// have it, since no specification says (docs/research/refresh-tokens.md),
// so that one who has only seen a refresh token cannot end the End-User's
// offline access.
//
// The refresh token is redeemed, and its replacement and the access token
// recorded, in one transaction, which first locks the family's row, as
// revoking the family does. So of two redemptions of one refresh token,
// the second waits for the first, finds the token used, and revokes the
// family; and a refresh and a revocation of one family take turns, so that
// the revocation sees every access token the family has recorded, and no
// refresh issues one after it. A scope that exceeds the family's, or a
// resource refused, rolls the transaction back, so that the refresh token
// can still be redeemed. The tokens are signed after it commits, as
// issueTokens signs them.
func (p *Provider) refresh(ctx context.Context, client *registry.Client, refreshToken string, scopes []string, resource string) (*tokenResponse, error) {
	hash := hashCode(refreshToken)
	jti := rand.Text()
	var server *registry.ResourceServer
	// When the refresh is, read once the family's row is locked, so that a
	// refresh that waited for another as the family ended is not dated
	// before the wait.
	var now, exp time.Time
	var row queries.LockRefreshTokenFamilyRow
	var claims claimsRequest
	var replacement string
	// Whether the refresh token is refused, after the transaction commits
	// the revocation of its family.
	var reused bool
	err := pgx.BeginTxFunc(ctx, p.db, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		q := p.queries.WithTx(tx)
		var err error
		row, err = q.LockRefreshTokenFamily(ctx, hash)
		if errors.Is(err, pgx.ErrNoRows) {
			return errRefreshTokenNotRedeemable
		}
		if err != nil {
			return err
		}
		now = time.Now()
		exp = now.Add(TokenLifetime)
		if row.ClientID != client.ID || row.Revoked || !row.Expiry.After(now) {
			return errRefreshTokenNotRedeemable
		}
		n, err := q.MarkRefreshTokenUsed(ctx, hash)
		if err != nil {
			return err
		}
		if n == 0 {
			reused = true
			// Every token of the family descends from its code, so the
			// family is revoked as a valid replay of the code revokes it.
			return revokeCode(ctx, q, row.CodeHash)
		}
		// After the reuse check, so that a refresh token presented again
		// revokes its family even while its End-User is out of the
		// registry; refusing rolls back marking it used.
		if _, ok := p.registry.EndUser(row.Subject); !ok {
			return errRefreshTokenNotRedeemable
		}
		if len(scopes) == 0 {
			scopes = row.Scopes
		} else if !isSubset(scopes, row.Scopes) {
			return errScopeNotGranted
		}
		var granted bool
		if server, granted = p.grantedResource(client, row.Resource, resource, scopes); !granted {
			return errResourceNotGranted
		}
		var userInfoClaims []byte
		if claims, userInfoClaims, err = decodeStoredClaims(row.Claims); err != nil {
			return err
		}
		if replacement, err = insertRefreshToken(ctx, q, row.ID); err != nil {
			return err
		}
		return q.InsertAccessToken(ctx, queries.InsertAccessTokenParams{
			Jti:            jti,
			CodeHash:       row.CodeHash,
			UserinfoClaims: userInfoClaims,
			Expiry:         exp,
		})
	})
	if err != nil {
		return nil, err
	}
	if reused {
		p.stopKeepingCode(ctx, row.CodeHash, now)
		return nil, errRefreshTokenNotRedeemable
	}
	// The ID token has no nonce, which §12.2 allows only with the value
	// of the original, and recommends against.
	return p.signTokens(client, issuance{
		subject:       row.Subject,
		resource:      server,
		scopes:        scopes,
		expiry:        exp,
		authTime:      row.AuthTime,
		idTokenClaims: claims.IDToken,
		jti:           jti,
		refreshToken:  replacement,
	}, now)
}

// revokeCode revokes the tokens issued from the code whose hash is
// codeHash: the Refresh Token Family it started, if any, and the access
// tokens issued from it, directly or in the family, whose records are
// deleted, so that UserInfo refuses them. The family is revoked first,
// which waits for a refresh in progress in it, so that the deletion then
// sees the access token that refresh recorded, and a later refresh finds
// the family revoked.
func revokeCode(ctx context.Context, q *queries.Queries, codeHash []byte) error {
	if err := q.RevokeRefreshTokenFamilyOfCode(ctx, codeHash); err != nil {
		return err
	}
	return q.DeleteAccessTokensOfCode(ctx, codeHash)
}

// decodeStoredClaims returns the claims request stored with a code or a
// Refresh Token Family, and the claims it requests from UserInfo, as they
// are recorded with an access token: UserInfo returns them with those of
// the token's scopes.
func decodeStoredClaims(data []byte) (claimsRequest, []byte, error) {
	claims, err := decodeClaimsRequest(data)
	if err != nil {
		return claims, nil, err
	}
	userInfoClaims, err := claims.UserInfo.encode()
	return claims, userInfoClaims, err
}

// insertRefreshToken records a new refresh token in the Refresh Token
// Family whose id is familyID, and returns it.
func insertRefreshToken(ctx context.Context, q *queries.Queries, familyID int64) (string, error) {
	token, hash := newRefreshToken()
	return token, q.InsertRefreshToken(ctx, queries.InsertRefreshTokenParams{TokenHash: hash, FamilyID: familyID})
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

// stopKeepingCode lets the code whose hash is codeHash be deleted from now
// on, its Refresh Token Family having been revoked by a refresh token
// presented again or at the revocation endpoint, so that it is no longer
// kept for the family. It runs after the revocation commits, so that a
// refresh never waits for a code's row while it holds its family's, which
// a replay of the code locks in the other order. A failure leaves the code
// until its family ends, when it would be deleted anyway, and does not
// fail the request.
func (p *Provider) stopKeepingCode(ctx context.Context, codeHash []byte, now time.Time) {
	if err := p.queries.StopKeepingAuthorizationCode(ctx, queries.StopKeepingAuthorizationCodeParams{CodeHash: codeHash, Now: now}); err != nil {
		p.logger.ErrorContext(ctx, "stop keeping authorization code", "error", err)
	}
}

// issuance is what a token response is issued for, and the tokens
// recorded for it that signTokens does not sign.
type issuance struct {
	subject string
	// resource is the Resource Server the access token is for, or nil if
	// it is for pulsar's UserInfo.
	resource *registry.ResourceServer
	// scopes are those granted for the access token: all of them, or, for
	// a Resource Server, those of them that are its own.
	scopes []string
	// expiry is when the access token and the ID token expire, as the
	// access token is recorded.
	expiry   time.Time
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
// an access token and an ID token, each expiring at t.expiry, and t's
// refresh token, if any.
//
// An access token for a Resource Server names its identifier, alone, as
// its audience, and holds only its scopes, so that it allows no more than
// that Resource Server needs and is refused anywhere else, UserInfo
// included (RFC 8707 §2, §2.2; RFC 9068 §3; RFC 9700 §2.3); it holds at
// least one (grantedResource). The token response's scope is the access
// token's (RFC 6749 §5.1). The ID token is the same either way.
func (p *Provider) signTokens(client *registry.Client, t issuance, now time.Time) (*tokenResponse, error) {
	exp := t.expiry
	audience := p.issuer.String()
	scopes := t.scopes
	if t.resource != nil {
		audience = t.resource.Identifier
		scopes = slices.DeleteFunc(slices.Clone(scopes), func(s string) bool { return !t.resource.HasScope(s) })
	}
	accessToken, err := p.signAccessToken(client.ID, t.subject, audience, scopes, t.jti, now, exp)
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
	// issueTokens and refresh refuse an End-User no longer in the registry,
	// so one is found here; were one not, it would have no claims to
	// release, and no error follows from that (§5.5.1).
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
		ExpiresIn:    int64(exp.Sub(now) / time.Second),
		IDToken:      idToken,
		RefreshToken: t.refreshToken,
		Scope:        strings.Join(scopes, " "),
	}, nil
}

// signAccessToken returns a JWT access token (RFC 9068 §2) issued to
// the Client whose client_id is clientID at now, until exp, for subject,
// with audience as its aud, scopes as its scope, and jti.
func (p *Provider) signAccessToken(clientID, subject, audience string, scopes []string, jti string, now, exp time.Time) (string, error) {
	return p.keys.SignJWT("at+jwt", accessTokenClaims{
		Issuer:   p.issuer.String(),
		Expiry:   exp.Unix(),
		Audience: audience,
		Subject:  subject,
		ClientID: clientID,
		IssuedAt: now.Unix(),
		JTI:      jti,
		Scope:    strings.Join(scopes, " "),
	})
}

// accessTokenClaims are the claims of a JWT access token (RFC 9068 §2.2).
// Its audience is the identifier of the Resource Server the request's
// resource parameter named, or the issuer, the default resource of a
// request without one (RFC 9068 §3).
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
