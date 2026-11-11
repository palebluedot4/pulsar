package oidc

import (
	"net/url"
	"testing"
)

// REQ-CORE-66, REQ-CORE-67: the response's parameters are added to the
// query of the redirect URI, which is kept as registered (RFC 6749
// §3.1.2): after "?" if it has no query, after "&" if it has one, and
// directly if it ends in either. No Client in the server's tests
// registers a redirect URI that ends in "?" or "&".
func TestWithQuery(t *testing.T) {
	t.Parallel()

	params := url.Values{"code": {"c"}}
	tests := []struct {
		uri  string
		want string
	}{
		{uri: "https://rp.example/cb", want: "https://rp.example/cb?code=c"},
		{uri: "https://rp.example/cb?tenant=a", want: "https://rp.example/cb?tenant=a&code=c"},
		{uri: "https://rp.example/cb?", want: "https://rp.example/cb?code=c"},
		{uri: "https://rp.example/cb?tenant=a&", want: "https://rp.example/cb?tenant=a&code=c"},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			t.Parallel()
			if got := withQuery(tt.uri, params); got != tt.want {
				t.Errorf("withQuery(%q, %v) = %q, want %q", tt.uri, params, got, tt.want)
			}
		})
	}
}
