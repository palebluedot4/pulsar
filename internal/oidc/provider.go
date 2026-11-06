package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palebluedot4/pulsar/internal/login"
	"github.com/palebluedot4/pulsar/internal/oidc/internal/queries"
	"github.com/palebluedot4/pulsar/internal/registry"
)

// Lifetimes of what the endpoints issue.
const (
	// codeLifetime is how long an authorization code may be redeemed:
	// short, as RFC 6749 §4.1.2 requires, so that a leaked code is soon
	// useless.
	codeLifetime = 60 * time.Second
	// TokenLifetime is how long an ID token or access token is valid: the
	// longest lifetime of anything the OP signs, so that a key that no
	// longer signs stays published for at least as long (internal/signing).
	TokenLifetime = 10 * time.Minute
	// familyLifetime is how long a Refresh Token Family lasts from the
	// redemption of the code that started it, however often it is
	// refreshed, so that no Client keeps offline access indefinitely from
	// one decision of the End-User's.
	familyLifetime = 30 * 24 * time.Hour
)

// codeSize is the number of random bytes in an authorization code: 256
// bits, so that the chance of guessing one is below the 2^(-160) that RFC
// 6749 §10.10 recommends.
const codeSize = 32

// JWTKeys signs JWTs with the OP's active signing key, and verifies them
// against the keys it publishes, as signing.KeySet does. It is an
// interface because signing depends, through config, on this package's
// Issuer.
type JWTKeys interface {
	// SignJWT returns a JWT in the JWS Compact Serialization whose claims
	// are claims, encoded as JSON, and whose header names typ as its type.
	SignJWT(typ string, claims any) (string, error)
	// VerifyJWT reports whether token is a JWT that one of the published
	// keys signed, and if so returns its header's typ and its claims, as
	// JSON.
	VerifyJWT(token string) (typ string, claims []byte, ok bool)
}

// Provider serves the authorization, token and UserInfo endpoints, which
// share the authorization codes the first issues and the second redeems,
// and the access tokens the second issues and the third accepts. It is
// safe for concurrent use.
type Provider struct {
	issuer   *Issuer
	registry *registry.Registry
	sessions *login.Sessions
	consents *login.Consents
	keys     JWTKeys
	db       *pgxpool.Pool
	queries  *queries.Queries
	logger   *slog.Logger
}

// NewProvider returns the endpoints of the OP at issuer, for the Clients
// and End-Users of reg, reading Login Sessions from sessions and Consents
// from consents, signing and verifying with keys, and keeping codes and
// access tokens in the database behind db. It logs to logger any error
// that ends a request.
func NewProvider(issuer *Issuer, reg *registry.Registry, sessions *login.Sessions, consents *login.Consents, keys JWTKeys, db *pgxpool.Pool, logger *slog.Logger) *Provider {
	return &Provider{
		issuer:   issuer,
		registry: reg,
		sessions: sessions,
		consents: consents,
		keys:     keys,
		db:       db,
		queries:  queries.New(db),
		logger:   logger,
	}
}

// AuthorizationPath returns the path at which the authorization endpoint
// for issuer is served: the path of the authorization_endpoint that the
// discovery document publishes.
func AuthorizationPath(issuer *Issuer) string {
	return issuer.Route(authorizationPath)
}

// TokenPath returns the path at which the token endpoint for issuer is
// served: the path of the token_endpoint that the discovery document
// publishes.
func TokenPath(issuer *Issuer) string {
	return issuer.Route(tokenPath)
}

// UserInfoPath returns the path at which the UserInfo endpoint for issuer
// is served: the path of the userinfo_endpoint that the discovery document
// publishes.
func UserInfoPath(issuer *Issuer) string {
	return issuer.Route(userinfoPath)
}

// newCode returns a new authorization code and the hash under which it is
// stored.
func newCode() (code string, hash []byte) {
	b := make([]byte, codeSize)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error.
	code = base64.RawURLEncoding.EncodeToString(b)
	return code, hashCode(code)
}

// newRefreshToken returns a new refresh token and the hash under which it
// is stored, made and stored as a code is.
func newRefreshToken() (token string, hash []byte) {
	return newCode()
}

// hashCode returns the hash under which code is stored, so that a copy of
// the database holds no code that could be redeemed.
func hashCode(code string) []byte {
	sum := sha256.Sum256([]byte(code))
	return sum[:]
}
