package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palebluedot4/pulsar/internal/config"
	"github.com/palebluedot4/pulsar/internal/guessing"
	"github.com/palebluedot4/pulsar/internal/oidc"
	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
	"github.com/palebluedot4/pulsar/internal/registry"
	"github.com/palebluedot4/pulsar/internal/signing"
)

func mustParse(tb testing.TB, raw string) *oidc.Issuer {
	tb.Helper()
	issuer, err := oidc.ParseIssuer(raw)
	if err != nil {
		tb.Fatal(err)
	}
	return issuer
}

// ready returns a channel that is already closed: the schema is migrated
// and the signing keys are loaded.
func ready() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

// newHandler returns the handler for the OP at issuer, backed by pool, with
// a key set that is never loaded.
func newHandler(t *testing.T, issuer *oidc.Issuer, pool *pgxpool.Pool, ready <-chan struct{}) http.Handler {
	t.Helper()
	return New(slog.New(slog.NewTextHandler(t.Output(), nil)), issuer, pool, signing.New(pool, config.Secret{}), &registry.Registry{}, guessing.New(pool, nil), ready)
}

// newHandlerWithoutDatabase returns the handler for the OP at issuer, with
// PostgreSQL unreachable, for endpoints that must not depend on it.
func newHandlerWithoutDatabase(t *testing.T, issuer string) http.Handler {
	t.Helper()
	return newHandler(t, mustParse(t, issuer), postgrestest.Open(t, postgrestest.UnreachableURL(t)), ready())
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
	reachable := newHandler(t, issuer, reachablePool, ready())
	starting := newHandler(t, issuer, reachablePool, make(chan struct{}))
	unreachable := newHandler(t, issuer, postgrestest.Open(t, postgrestest.UnreachableURL(t)), ready())

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
	saturated := newHandler(t, issuer, saturatedPool, ready())

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
		{name: "reachable, not yet migrated or without keys", handler: starting, method: http.MethodGet, want: http.StatusServiceUnavailable},
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
