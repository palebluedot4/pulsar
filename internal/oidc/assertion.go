package oidc

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/palebluedot4/pulsar/internal/oidc/internal/queries"
	"github.com/palebluedot4/pulsar/internal/registry"
)

// jwtBearer is the client_assertion_type of a JWT that authenticates a
// Client (RFC 7523 §2.2, OpenID Connect Core 1.0 §9).
const jwtBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" //nolint:gosec // G101: a URN that names a format, not a credential.

// maxAssertionLifetime is how far ahead of now a client assertion's exp
// may be. RFC 7523 §3 lets an authorization server refuse an exp
// "unreasonably far in the future"; refusing one bounds how long its jti
// is kept.
const maxAssertionLifetime = time.Hour

// nbfLeeway is how far ahead of pulsar's clock a client assertion's nbf
// may be, for clock skew between the Client and pulsar. exp gets none, so
// that a jti is kept exactly as long as its assertion could be accepted;
// nbf can have some without that cost.
const nbfLeeway = time.Minute

// authenticateAssertion authenticates a Client registered for
// private_key_jwt by the JWT in the client_assertion parameter (RFC 7523
// §3, OpenID Connect Core 1.0 §9), and records its jti so that it
// authenticates only once. An assertion that fails any check gets
// invalid_client (RFC 7521 §4.2.1).
func (p *Provider) authenticateAssertion(ctx context.Context, params url.Values) (*registry.Client, *tokenError) {
	if params.Get("client_assertion_type") != jwtBearer {
		return nil, unauthorized()
	}
	now := time.Now()
	client, claims, ok := p.verifyAssertion(params.Get("client_assertion"), now)
	if !ok {
		return nil, unauthorized()
	}
	// RFC 7521 §4.2: a client_id, which is optional, names the Client the
	// assertion does.
	if id := params.Get("client_id"); id != "" && id != client.ID {
		return nil, unauthorized()
	}

	jtiHash := sha256.Sum256([]byte(claims.ID))
	n, err := p.queries.InsertClientAssertion(ctx, queries.InsertClientAssertionParams{
		ClientID: client.ID,
		JtiHash:  jtiHash[:],
		Expiry:   claims.Expiry.Time(),
		Now:      now,
	})
	if err != nil {
		p.logger.ErrorContext(ctx, "record client assertion", "error", err)
		return nil, &tokenError{status: http.StatusInternalServerError, Code: errServerError}
	}
	if n == 0 {
		// The assertion, or another of this Client's with its jti, has
		// authenticated before and not yet expired.
		return nil, unauthorized()
	}
	return client, nil
}

// verifyAssertion returns the Client that the client assertion raw
// authenticates at now, and its claims, if raw is one JWS in the compact
// serialization, signed by an algorithm of the allow-list (RFC 8725 §3.2)
// with a key that Client registered for that algorithm (RFC 8725 §3.1,
// §3.8), and its claims are those RFC 7523 §3, as RFC 10070 §4 updates it,
// and OpenID Connect Core 1.0 §9 require.
func (p *Provider) verifyAssertion(raw string, now time.Time) (*registry.Client, *jwt.Claims, bool) {
	tok, err := jwt.ParseSigned(raw, registry.AssertionAlgorithms())
	if err != nil {
		return nil, nil, false
	}
	// The assertion names its Client, whose keys then verify it; nothing
	// else it says is read before they do.
	var named jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&named); err != nil {
		return nil, nil, false
	}
	client, ok := p.registry.Client(named.Subject)
	if !ok || client.AuthMethod != registry.PrivateKeyJWT {
		return nil, nil, false
	}
	var claims jwt.Claims
	if !verifyWithClientKey(tok, client.JWKS, &claims) {
		return nil, nil, false
	}

	switch {
	// Compared as strings (RFC 7523 §3), with client.ID the registered
	// value.
	case claims.Issuer != client.ID || claims.Subject != client.ID:
		return nil, nil, false
	// RFC 10070 §4: the issuer is the sole audience, compared as a string,
	// and the token endpoint URL is refused. A string and an array of one
	// both decode to one value.
	case len(claims.Audience) != 1 || claims.Audience[0] != p.issuer.String():
		return nil, nil, false
	// Core §9: "on or after which the JWT MUST NOT be accepted". No clock
	// skew is allowed, so that a jti is kept exactly as long as its
	// assertion could be accepted.
	case claims.Expiry == nil || !now.Before(claims.Expiry.Time()):
		return nil, nil, false
	case claims.Expiry.Time().After(now.Add(maxAssertionLifetime)):
		return nil, nil, false
	case claims.NotBefore != nil && now.Add(nbfLeeway).Before(claims.NotBefore.Time()):
		return nil, nil, false
	case claims.ID == "":
		return nil, nil, false
	}
	return client, &claims, true
}

// verifyWithClientKey verifies tok with the keys of set that its header's
// kid names, or with every key if it names none, and decodes its claims
// into dest. A key verifies only with the algorithm it was registered for
// (RFC 8725 §3.1).
func verifyWithClientKey(tok *jwt.JSONWebToken, set *jose.JSONWebKeySet, dest *jwt.Claims) bool {
	// A compact serialization has exactly one header.
	h := tok.Headers[0]
	keys := set.Keys
	if h.KeyID != "" {
		keys = set.Key(h.KeyID)
	}
	for _, k := range keys {
		if k.Algorithm == h.Algorithm && tok.Claims(k.Key, dest) == nil {
			return true
		}
	}
	return false
}
