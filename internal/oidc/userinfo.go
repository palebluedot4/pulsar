package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5"

	"github.com/palebluedot4/pulsar/internal/oidc/internal/queries"
)

// errInvalidToken is the error code of a protected resource's response to
// an access token that is expired, revoked, malformed or otherwise invalid
// (RFC 6750 §3.1).
const errInvalidToken = "invalid_token"

// bearerError is an error response of the UserInfo endpoint (OpenID
// Connect Core 1.0 §5.3.3, RFC 6750 §3).
type bearerError struct {
	status int
	// code is the error code, or "" for a request that sent no access
	// token, which RFC 6750 §3.1 answers without one.
	code string
	desc string // fixed text that never repeats the request
}

// errNoToken answers a request that sent no access token, or sent
// credentials by a scheme other than Bearer (RFC 6750 §3.1).
var errNoToken = &bearerError{status: http.StatusUnauthorized}

// errServer answers a request that fails for a reason of pulsar's own.
var errServer = &bearerError{status: http.StatusInternalServerError}

// errBadToken answers a request whose access token fails validation (RFC
// 9068 §4, RFC 6750 §3.1).
var errBadToken = &bearerError{status: http.StatusUnauthorized, code: errInvalidToken, desc: "The access token is invalid, expired or revoked."}

// HandleUserInfo serves the UserInfo endpoint, by GET and POST (OpenID
// Connect Core 1.0 §5.3). It accepts an access token pulsar issued, sent
// as a bearer token in the Authorization header or, by POST, in the
// form-encoded body (RFC 6750 §2.1, §2.2), and returns the End-User's sub
// and the claims the token's scopes request (§5.4).
func (p *Provider) HandleUserInfo() http.Handler {
	return http.HandlerFunc(p.userInfo)
}

func (p *Provider) userInfo(w http.ResponseWriter, r *http.Request) {
	// Every response is about an End-User or a credential, and no cache
	// may keep it.
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")

	claims, bErr := p.userInfoClaims(w, r)
	if bErr != nil && bErr.status == http.StatusInternalServerError {
		// An HTTP error unrelated to RFC 6750 (OpenID Connect Core 1.0
		// §5.3.3), so without a challenge: the credentials are not at
		// fault.
		w.WriteHeader(bErr.status)
		return
	}
	if bErr != nil {
		// RFC 6750 §3: every failure to authorize is answered with the
		// Bearer challenge, with the error code, if any; the realm is the
		// issuer, as at the token endpoint.
		challenge := `Bearer realm="` + p.issuer.String() + `"`
		if bErr.code != "" {
			challenge += `, error="` + bErr.code + `", error_description="` + bErr.desc + `"`
		}
		h.Set("WWW-Authenticate", challenge)
		w.WriteHeader(bErr.status)
		return
	}
	writeJSON(w, http.StatusOK, claims)
}

// userInfoClaims returns the claims UserInfo answers r with, or the error
// it answers with instead.
func (p *Provider) userInfoClaims(w http.ResponseWriter, r *http.Request) (map[string]any, *bearerError) {
	ctx := r.Context()
	token, bErr := bearerToken(w, r)
	if bErr != nil {
		return nil, bErr
	}
	at, err := p.verifyAccessToken(ctx, token)
	switch {
	case errors.Is(err, errTokenNotValid):
		return nil, errBadToken
	case err != nil:
		p.logger.ErrorContext(ctx, "UserInfo endpoint", "error", err)
		return nil, errServer
	}
	// An End-User removed from the registry since the token was issued has
	// no claims to return, and the token no End-User to stand for.
	u, ok := p.registry.EndUser(at.subject)
	if !ok {
		return nil, errBadToken
	}
	all, err := endUserClaims(u)
	if err != nil {
		p.logger.ErrorContext(ctx, "UserInfo endpoint", "error", err)
		return nil, errServer
	}
	// sub always (§5.3.2), and the claims requested.
	claims := map[string]any{"sub": u.Subject}
	at.requested().release(claims, all)
	return claims, nil
}

// bearerToken returns the access token r sends: in the Authorization
// header by the Bearer scheme (RFC 6750 §2.1), or, by POST, as
// access_token in a form-encoded body (§2.2). Credentials of another
// scheme authenticate nothing here. A request that sends no token gets
// errNoToken; one that sends more than one, by one method or two, or a
// malformed one, gets invalid_request (§3.1). A request with a token in
// its header may have any body, even one that cannot be read as a form.
func bearerToken(w http.ResponseWriter, r *http.Request) (string, *bearerError) {
	var tokens []string
	for _, v := range r.Header.Values("Authorization") {
		// The scheme is case-insensitive (RFC 9110 §11.1).
		scheme, token, _ := strings.Cut(v, " ")
		if strings.EqualFold(scheme, "Bearer") {
			tokens = append(tokens, strings.TrimLeft(token, " "))
		}
	}
	if r.Method == http.MethodPost {
		params, err := readParams(w, r)
		switch {
		case errors.Is(err, errNotForm), err != nil && len(tokens) > 0:
			// A body of another type carries no token (§2.2).
		case err != nil:
			return "", &bearerError{status: http.StatusBadRequest, code: errInvalidRequest, desc: "The request body could not be read."}
		default:
			tokens = append(tokens, params["access_token"]...)
		}
	}
	switch {
	case len(tokens) == 0:
		return "", errNoToken
	case len(tokens) > 1:
		return "", &bearerError{status: http.StatusBadRequest, code: errInvalidRequest, desc: "The access token must be sent once, by one method."}
	case tokens[0] == "":
		return "", &bearerError{status: http.StatusBadRequest, code: errInvalidRequest, desc: "The Authorization header has no access token."}
	}
	return tokens[0], nil
}

// errTokenNotValid is returned by verifyAccessToken for an access token
// that fails validation.
var errTokenNotValid = errors.New("the access token is not valid")

// verifiedAccessToken is what UserInfo reads of an access token that
// verifyAccessToken accepted, and of its record.
type verifiedAccessToken struct {
	subject string
	scope   string
	claims  requestedClaims // requested from UserInfo by the claims parameter
}

// requested returns the claims UserInfo returns for the token, if the
// End-User has them: those of each scope granted, whatever their values
// (§5.4), and those the claims parameter requested from UserInfo, in
// addition (§5.5).
func (at verifiedAccessToken) requested() requestedClaims {
	requested := maps.Clone(at.claims)
	if requested == nil {
		requested = make(requestedClaims)
	}
	for scope := range strings.FieldsSeq(at.scope) {
		for _, name := range scopeClaims[scope] {
			requested[name] = claimRequest{}
		}
	}
	return requested
}

// verifyAccessToken validates token as RFC 9068 §4 requires of a resource
// server, with this OP as the resource, and checks that its record is
// current: it is recorded, and has not expired.
func (p *Provider) verifyAccessToken(ctx context.Context, token string) (verifiedAccessToken, error) {
	// A signature by a key the OP publishes, by RS256, never none.
	typ, payload, ok := p.keys.VerifyJWT(token)
	if !ok {
		return verifiedAccessToken{}, errTokenNotValid
	}
	// The media type, with or without its prefix, compared without regard
	// to case (RFC 7515 §4.1.9).
	if !strings.EqualFold(typ, "at+jwt") && !strings.EqualFold(typ, "application/at+jwt") {
		return verifiedAccessToken{}, errTokenNotValid
	}
	var claims struct {
		jwt.Claims
		Scope string `json:"scope"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return verifiedAccessToken{}, errTokenNotValid
	}
	now := time.Now()
	issuer := p.issuer.String()
	switch {
	case claims.Issuer != issuer || !claims.Audience.Contains(issuer):
		return verifiedAccessToken{}, errTokenNotValid
	// "The current time MUST be before" exp, so a token is refused from its
	// exp on, and one without exp is refused; jwt.Claims.Validate would
	// accept both.
	case claims.Expiry == nil || !now.Before(claims.Expiry.Time()):
		return verifiedAccessToken{}, errTokenNotValid
	case claims.Subject == "" || claims.ID == "":
		return verifiedAccessToken{}, errTokenNotValid
	}
	// A token that a second redemption of its code has revoked has no
	// record (RFC 6749 §4.1.2), so it is refused here.
	data, err := p.queries.FindAccessToken(ctx, queries.FindAccessTokenParams{Jti: claims.ID, Now: now})
	if errors.Is(err, pgx.ErrNoRows) {
		return verifiedAccessToken{}, errTokenNotValid
	}
	if err != nil {
		return verifiedAccessToken{}, err
	}
	requested, err := decodeRequestedClaims(data)
	if err != nil {
		return verifiedAccessToken{}, err
	}
	return verifiedAccessToken{subject: claims.Subject, scope: claims.Scope, claims: requested}, nil
}
