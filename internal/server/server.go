// Package server assembles pulsar's HTTP handler.
package server

import (
	"net/http"
	"net/url"
)

// New returns the handler that serves every pulsar endpoint for the OP
// whose Issuer Identifier is issuer.
func New(issuer *url.URL) http.Handler {
	mux := http.NewServeMux()
	addRoutes(mux, issuer)
	return mux
}
