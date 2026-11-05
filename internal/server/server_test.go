package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/palebluedot4/pulsar/internal/oidc"
	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
)

func mustParse(t *testing.T, raw string) *oidc.Issuer {
	t.Helper()
	issuer, err := oidc.ParseIssuer(raw)
	if err != nil {
		t.Fatal(err)
	}
	return issuer
}

// migrated returns a channel that is already closed: the schema is
// migrated.
func migrated() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

// newHandlerWithoutDatabase returns the handler for the OP at issuer, with
// PostgreSQL unreachable, for endpoints that must not depend on it.
func newHandlerWithoutDatabase(t *testing.T, issuer string) http.Handler {
	t.Helper()
	return New(mustParse(t, issuer), postgrestest.Open(t, postgrestest.UnreachableURL(t)), migrated())
}

func TestLive(t *testing.T) {
	t.Parallel()

	// Liveness checks no dependency, so it holds with PostgreSQL unreachable.
	handler := newHandlerWithoutDatabase(t, "https://op.example")
	tests := []struct {
		method string
		want   int
	}{
		{method: http.MethodGet, want: http.StatusOK},
		{method: http.MethodHead, want: http.StatusOK},
		{method: http.MethodPost, want: http.StatusMethodNotAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), tt.method, "/livez", http.NoBody)
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Errorf("%s /livez status = %d, want %d", tt.method, rec.Code, tt.want)
			}
		})
	}
}

func TestReady(t *testing.T) {
	t.Parallel()

	issuer := mustParse(t, "https://op.example")
	reachablePool := postgrestest.Open(t, postgrestest.NewDatabase(t))
	reachable := New(issuer, reachablePool, migrated())
	migrating := New(issuer, reachablePool, make(chan struct{}))
	unreachable := New(issuer, postgrestest.Open(t, postgrestest.UnreachableURL(t)), migrated())

	// A pool of one connection, held by the test: PostgreSQL answers, but
	// the replica could not serve a request that needs it.
	saturatedURL, err := url.Parse(postgrestest.NewDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	q := saturatedURL.Query()
	q.Set("pool_max_conns", "1")
	saturatedURL.RawQuery = q.Encode()
	saturatedPool := postgrestest.Open(t, saturatedURL.String())
	held, err := saturatedPool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(held.Release)
	saturated := New(issuer, saturatedPool, migrated())

	tests := []struct {
		name    string
		handler http.Handler
		method  string
		want    int
	}{
		{name: "reachable", handler: reachable, method: http.MethodGet, want: http.StatusOK},
		{name: "reachable", handler: reachable, method: http.MethodHead, want: http.StatusOK},
		{name: "reachable", handler: reachable, method: http.MethodPost, want: http.StatusMethodNotAllowed},
		{name: "unreachable", handler: unreachable, method: http.MethodGet, want: http.StatusServiceUnavailable},
		{name: "unreachable", handler: unreachable, method: http.MethodHead, want: http.StatusServiceUnavailable},
		{name: "saturated", handler: saturated, method: http.MethodGet, want: http.StatusServiceUnavailable},
		{name: "reachable, not yet migrated", handler: migrating, method: http.MethodGet, want: http.StatusServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/"+tt.method, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), tt.method, "/readyz", http.NoBody)
			tt.handler.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Errorf("%s /readyz with PostgreSQL %s: status = %d, want %d", tt.method, tt.name, rec.Code, tt.want)
			}
		})
	}
}
