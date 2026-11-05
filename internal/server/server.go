// Package server assembles pulsar's HTTP handler.
package server

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palebluedot4/pulsar/internal/oidc"
)

// New returns the handler that serves every pulsar endpoint for the OP
// whose Issuer Identifier is issuer, backed by the PostgreSQL database
// behind pool. migrated is closed once the database's schema is migrated;
// until then the replica reports itself not ready.
func New(issuer *oidc.Issuer, pool *pgxpool.Pool, migrated <-chan struct{}) http.Handler {
	mux := http.NewServeMux()
	addRoutes(mux, issuer, pool, migrated)
	return mux
}
