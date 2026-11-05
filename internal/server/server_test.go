package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestLive(t *testing.T) {
	t.Parallel()

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
			New(mustParse(t, "https://op.example")).ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Errorf("%s /livez status = %d, want %d", tt.method, rec.Code, tt.want)
			}
		})
	}
}
