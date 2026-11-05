package server

import "net/http"

// addRoutes maps pulsar's entire HTTP surface.
func addRoutes(mux *http.ServeMux) {
	mux.Handle("GET /livez", handleLive())
}

// handleLive reports that the process is serving requests. It checks no
// dependencies; readiness is a separate question.
func handleLive() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}
