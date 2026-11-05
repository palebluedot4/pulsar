// Package server assembles pulsar's HTTP handler.
package server

import "net/http"

// New returns the handler that serves every pulsar endpoint.
func New() http.Handler {
	mux := http.NewServeMux()
	addRoutes(mux)
	return mux
}
