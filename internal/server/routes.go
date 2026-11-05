package server

import (
	"net/http"
	"net/url"

	"github.com/palebluedot4/pulsar/internal/oidc"
)

// addRoutes maps pulsar's entire HTTP surface. The protocol endpoints sit
// under the issuer's path; the operational ones at the root.
func addRoutes(mux *http.ServeMux, issuer *url.URL) {
	mux.Handle("GET /livez", handleLive())
	mux.Handle("GET "+oidc.DiscoveryPath(issuer), oidc.HandleDiscovery(issuer))
}

// handleLive reports that the process is serving requests. It checks no
// dependencies; readiness is a separate question.
func handleLive() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}
