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
	// tokenLifetime is how long an ID token or access token is valid.
	tokenLifetime = 10 * time.Minute
)

// codeSize is the number of random bytes in an authorization code: 256
// bits, so that the chance of guessing one is below the 2^(-160) that RFC
// 6749 §10.10 recommends.
const codeSize = 32

// JWTSigner signs JWTs with the OP's active signing key, as
// signing.KeySet does. It is an interface because signing depends,
// through config, on this package's Issuer.
type JWTSigner interface {
	// SignJWT returns a JWT in the JWS Compact Serialization whose claims
	// are claims, encoded as JSON, and whose header names typ as its type.
	SignJWT(typ string, claims any) (string, error)
}

// Provider serves the authorization and token endpoints, which share the
// authorization codes one issues and the other redeems. It is safe for
// concurrent use.
type Provider struct {
	issuer   *Issuer
	registry *registry.Registry
	sessions *login.Sessions
	consents *login.Consents
	keys     JWTSigner
	db       *pgxpool.Pool
	queries  *queries.Queries
	logger   *slog.Logger
}

// NewProvider returns the endpoints of the OP at issuer, for the Clients
// and End-Users of reg, reading Login Sessions from sessions and Consents
// from consents, signing with keys and keeping codes and access tokens in
// the database behind db. It logs to logger any error that ends a request.
func NewProvider(issuer *Issuer, reg *registry.Registry, sessions *login.Sessions, consents *login.Consents, keys JWTSigner, db *pgxpool.Pool, logger *slog.Logger) *Provider {
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

// newCode returns a new authorization code and the hash under which it is
// stored.
func newCode() (code string, hash []byte) {
	b := make([]byte, codeSize)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error.
	code = base64.RawURLEncoding.EncodeToString(b)
	return code, hashCode(code)
}

// hashCode returns the hash under which code is stored, so that a copy of
// the database holds no code that could be redeemed.
func hashCode(code string) []byte {
	sum := sha256.Sum256([]byte(code))
	return sum[:]
}
