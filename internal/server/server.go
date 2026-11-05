// Package server assembles pulsar's HTTP handler.
package server

import (
	"net/http"

	"github.com/palebluedot4/pulsar/internal/oidc"
)

// New returns the handler that serves every pulsar endpoint for the OP
// whose Issuer Identifier is issuer.
func New(issuer *oidc.Issuer) http.Handler {
	mux := http.NewServeMux()
	addRoutes(mux, issuer)
	return mux
}
