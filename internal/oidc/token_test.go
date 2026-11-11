package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// A token error that asks the Client to retry later carries Retry-After in
// whole seconds (RFC 9110 §10.2.3), and one that does not carries none. No
// test reaches it through the token endpoint: it answers a token request
// that finds no room to check the Client's secret, and a test cannot hold
// the room the registry keeps for that. It cites no requirement: RFC 9110
// is not among the specifications in scope.
func TestWriteTokenErrorRetryAfter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		retryAfter time.Duration
		want       []string
	}{
		{name: "a second", retryAfter: time.Second, want: []string{"1"}},
		{name: "none", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			(&Provider{}).writeTokenError(rec, &tokenError{status: http.StatusServiceUnavailable, retryAfter: tt.retryAfter, Code: errTemporarilyUnavailable})
			if diff := cmp.Diff(tt.want, rec.Header().Values("Retry-After")); diff != "" {
				t.Errorf("writeTokenError(retryAfter %v) Retry-After mismatch (-want +got):\n%s", tt.retryAfter, diff)
			}
		})
	}
}
