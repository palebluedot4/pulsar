package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palebluedot4/pulsar/internal/guessing"
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
func addRoutes(mux *http.ServeMux, logger *slog.Logger, issuer *oidc.Issuer, pool *pgxpool.Pool, keys *signing.KeySet, reg *registry.Registry, limiter *guessing.Limiter, ready <-chan struct{}) {
	mux.Handle("GET /livez", handleLive())
	mux.Handle("GET /readyz", handleReady(pool, ready))
	mux.Handle("GET "+oidc.DiscoveryPath(issuer), oidc.HandleDiscovery(issuer))
	mux.Handle("GET "+oidc.JWKSPath(issuer), keys.HandleJWKS())

	// The login page and the protocol endpoints below need the database's
	// tables, and the token endpoint the signing keys, so they wait, as
	// readiness does, until the schema is migrated and the keys loaded.
	loginPath := issuer.Route(login.Path)
	authorizationPath := oidc.AuthorizationPath(issuer)
	sessions := login.NewSessions(pool, reg)
	loginPage := whenReady(ready, sessions.Handler(loginPath, authorizationPath, limiter, logger))
	mux.Handle("GET "+loginPath, loginPage)
	mux.Handle("POST "+loginPath, loginPage)
	consentPath := issuer.Route(login.ConsentPath)
	mux.Handle("POST "+consentPath, whenReady(ready, sessions.ConsentHandler(authorizationPath, logger)))

	// The protocol endpoints are not protected against cross-site request
	// forgery: a Client sends them requests from its own origin. The token,
	// revocation and UserInfo endpoints answer a browser-based Client's
	// cross-origin requests, and their preflights, which need neither the
	// database nor the signing keys; the authorization endpoint, to which a
	// Client redirects the browser, answers none (RFC 9700 §2.6).
	op := oidc.NewProvider(issuer, reg, sessions, login.NewConsents(pool), keys, pool, logger)
	authorization := whenReady(ready, op.HandleAuthorization(loginPath, consentPath))
	mux.Handle("GET "+authorizationPath, authorization)
	mux.Handle("POST "+authorizationPath, authorization)
	mux.Handle("POST "+oidc.TokenPath(issuer), whenReady(ready, op.HandleToken()))
	clientPreflight := op.HandleClientPreflight()
	mux.Handle("OPTIONS "+oidc.TokenPath(issuer), clientPreflight)
	mux.Handle("POST "+oidc.RevocationPath(issuer), whenReady(ready, op.HandleRevocation()))
	mux.Handle("OPTIONS "+oidc.RevocationPath(issuer), clientPreflight)
	userInfo := whenReady(ready, op.HandleUserInfo())
	mux.Handle("GET "+oidc.UserInfoPath(issuer), userInfo)
	mux.Handle("POST "+oidc.UserInfoPath(issuer), userInfo)
	mux.Handle("OPTIONS "+oidc.UserInfoPath(issuer), op.HandleUserInfoPreflight())

	// A Client sends the End-User to the logout endpoint from its own site,
	// by GET or POST; the confirmation the endpoint asks for refuses
	// cross-origin submissions, as the consent form does.
	logout := whenReady(ready, op.HandleLogout())
	mux.Handle("GET "+oidc.LogoutPath(issuer), logout)
	mux.Handle("POST "+oidc.LogoutPath(issuer), logout)
	mux.Handle("POST "+oidc.LogoutConfirmationPath(issuer), whenReady(ready, op.HandleLogoutConfirmation()))
}

// whenReady answers 503, which no cache may keep, until ready is closed,
// and passes every request after that to h.
func whenReady(ready <-chan struct{}, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-ready:
			h.ServeHTTP(w, r)
		default:
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})
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
