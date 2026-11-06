package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palebluedot4/pulsar/internal/login"
	"github.com/palebluedot4/pulsar/internal/oidc"
	"github.com/palebluedot4/pulsar/internal/registry"
	"github.com/palebluedot4/pulsar/internal/signing"
)

// readyTimeout bounds the readiness check, so that a database that hangs
// makes the replica unready rather than the request hang.
const readyTimeout = 2 * time.Second

// addRoutes maps pulsar's entire HTTP surface. The protocol endpoints and
// the login page sit under the issuer's path; the operational ones at the
// root.
func addRoutes(mux *http.ServeMux, logger *slog.Logger, issuer *oidc.Issuer, pool *pgxpool.Pool, keys *signing.KeySet, reg *registry.Registry, ready <-chan struct{}) {
	mux.Handle("GET /livez", handleLive())
	mux.Handle("GET /readyz", handleReady(pool, ready))
	mux.Handle("GET "+oidc.DiscoveryPath(issuer), oidc.HandleDiscovery(issuer))
	mux.Handle("GET "+oidc.JWKSPath(issuer), keys.HandleJWKS())

	loginPath := issuer.Route(login.Path)
	loginPage := login.Handler(loginPath, pool, reg, logger)
	mux.Handle("GET "+loginPath, loginPage)
	mux.Handle("POST "+loginPath, loginPage)
}

// handleLive reports that the process is serving requests. It checks no
// dependencies; readiness is a separate question.
func handleLive() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// handleReady reports whether this replica can serve, so that a load
// balancer sends traffic elsewhere when it cannot: 503 until ready is
// closed; after that 200 when a ping through the pool succeeds within
// readyTimeout, and 503 otherwise.
//
// A ping first acquires a pool connection, so 503 means either that
// PostgreSQL did not answer or that every pooled connection stayed busy for
// readyTimeout. Both are deliberate: a replica whose pool is saturated
// cannot serve requests that need the database either.
func handleReady(pool *pgxpool.Pool, ready <-chan struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-ready:
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), readyTimeout)
		defer cancel()
		if err := pool.Ping(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}
