package oidc

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/palebluedot4/pulsar/internal/registry"
)

// revocationParams are the parameters of a revocation request that pulsar
// reads (RFC 7009 §2.1). Every other parameter is ignored.
var revocationParams = []string{
	"token", "token_type_hint",
	"client_id", "client_secret", "client_assertion_type", "client_assertion",
}

// errTokenNotFound is returned by a lookup of revoke for a token that is
// not of its type, that pulsar no longer keeps, or that is no longer valid:
// an access token that has expired, or a refresh token whose Refresh Token
// Family has ended. RFC 7009 §2.2 answers each as an invalid token, and
// none is checked against the Client, so that the answer does not depend
// on when the periodic deletion runs.
var errTokenNotFound = errors.New("the token is not found")

// errOtherClientsToken is returned by a lookup of revoke for a token
// issued to a Client other than the one that authenticated.
var errOtherClientsToken = errors.New("the token was issued to another client")

// HandleRevocation serves the revocation endpoint, by POST (RFC 7009 §2).
// A Client authenticates as at the token endpoint, and revokes a refresh
// token or an access token issued to it. A refresh token revokes its whole
// Refresh Token Family and the access tokens issued from its code; an
// access token revokes only itself, by deleting its record, so that
// UserInfo refuses it. A public Client running in a browser may send its
// requests from the origin of one of its redirect URIs, as at the token
// endpoint.
func (p *Provider) HandleRevocation() http.Handler {
	return http.HandlerFunc(p.revocation)
}

func (p *Provider) revocation(w http.ResponseWriter, r *http.Request) {
	setCredentialHeaders(w)
	r = withEndpoint(r, "revocation endpoint")
	if tokErr := p.revoke(w, r); tokErr != nil {
		p.writeTokenError(w, tokErr)
		return
	}
	// The body is ignored by the Client (RFC 7009 §2.2), so there is none.
	w.WriteHeader(http.StatusOK)
}

// revoke reads a revocation request, authenticates its Client and revokes
// the token it names, if it finds one. A token it does not find, of
// whichever type, is no error (RFC 7009 §2.2).
func (p *Provider) revoke(w http.ResponseWriter, r *http.Request) *tokenError {
	params, tokErr := p.readClientRequest(w, r, revocationParams)
	if tokErr != nil {
		return tokErr
	}
	// Checked before the Client authenticates, so that a malformed request
	// does not use up a client assertion.
	token := params.Get("token")
	if token == "" {
		return badRequest(errInvalidRequest, "The parameter token is required.")
	}
	client, tokErr := p.authenticateClient(r, params)
	if tokErr != nil {
		return tokErr
	}

	// The hint orders the lookups, and the other is tried when the hinted
	// one finds nothing (RFC 7009 §2.1); any other hint is ignored (§2.2).
	// Without one, a token in the JWS compact serialization is looked for
	// as an access token first, since a refresh token, base64url, has no
	// dot, and that lookup needs no database.
	lookups := []func(context.Context, *registry.Client, string) error{p.revokeRefreshToken, p.revokeAccessToken}
	switch params.Get("token_type_hint") {
	case "refresh_token":
	case "access_token":
		slices.Reverse(lookups)
	default:
		if strings.Count(token, ".") == 2 {
			slices.Reverse(lookups)
		}
	}
	ctx := r.Context()
	for _, lookup := range lookups {
		err := lookup(ctx, client, token)
		switch {
		case errors.Is(err, errTokenNotFound):
			continue
		case errors.Is(err, errOtherClientsToken):
			// RFC 7009 §2.1 refuses the request without naming an error
			// code; Keycloak and node-oidc-provider answer this one.
			return badRequest(errInvalidRequest, "The token was issued to another client.")
		case err != nil:
			return p.serverError(ctx, err)
		}
		return nil
	}
	return nil
}

// revokeRefreshToken revokes the Refresh Token Family of token, a refresh
// token of client's, used or not, and the access tokens issued from its
// code, as a refresh token presented again does (refresh): the family's
// row is locked first, so that a refresh in progress in it commits before,
// and one after finds it revoked. It returns errTokenNotFound if token is
// no refresh token pulsar keeps, or its family has ended, and
// errOtherClientsToken if it is another Client's.
func (p *Provider) revokeRefreshToken(ctx context.Context, client *registry.Client, token string) error {
	var codeHash []byte
	err := pgx.BeginTxFunc(ctx, p.db, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		q := p.queries.WithTx(tx)
		row, err := q.LockRefreshTokenFamily(ctx, hashCode(token))
		if errors.Is(err, pgx.ErrNoRows) {
			return errTokenNotFound
		}
		if err != nil {
			return err
		}
		// Ended, as refresh has it, whether or not it has been deleted yet.
		if !row.Expiry.After(time.Now()) {
			return errTokenNotFound
		}
		if row.ClientID != client.ID {
			return errOtherClientsToken
		}
		codeHash = row.CodeHash
		return revokeCode(ctx, q, row.CodeHash)
	})
	if err != nil {
		return err
	}
	p.stopKeepingCode(ctx, codeHash, time.Now())
	return nil
}

// revokeAccessToken revokes token, an access token of client's, alone, by
// deleting its record, so that UserInfo refuses it. It returns
// errTokenNotFound if token is no access token pulsar issued, or its
// claims are not valid now, as UserInfo checks them, expiry included; and
// errOtherClientsToken if it is another Client's.
func (p *Provider) revokeAccessToken(ctx context.Context, client *registry.Client, token string) error {
	signed, ok := p.parseAccessToken(token)
	if !ok || !p.validAccessTokenClaims(signed, time.Now()) {
		return errTokenNotFound
	}
	if signed.ClientID != client.ID {
		return errOtherClientsToken
	}
	return p.queries.DeleteAccessToken(ctx, signed.ID)
}
