// Package server assembles pulsar's HTTP handler.
package server

import (
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palebluedot4/pulsar/internal/oidc"
	"github.com/palebluedot4/pulsar/internal/registry"
	"github.com/palebluedot4/pulsar/internal/signing"
)

// New returns the handler that serves every pulsar endpoint for the OP
// whose Issuer Identifier is issuer, backed by the PostgreSQL database
// behind pool, signing with keys, and serving the Clients and End-Users of
// reg, logging to logger. ready is closed once the database's
// schema is migrated and keys is loaded; until then the replica reports
// itself not ready.
func New(logger *slog.Logger, issuer *oidc.Issuer, pool *pgxpool.Pool, keys *signing.KeySet, reg *registry.Registry, ready <-chan struct{}) http.Handler {
	mux := http.NewServeMux()
	addRoutes(mux, logger, issuer, pool, keys, reg, ready)
	return mux
}
