package server

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
)

// The loopback redirect URIs that the public Client loopback registered in
// flowRegistry, as a native app does (RFC 8252 §7.3): one without a port,
// and one with a port and another path.
const (
	loopbackRedirectURI     = "http://127.0.0.1/callback"
	loopbackIPv6RedirectURI = "http://[::1]:8000/v6/callback"
)

// asLoopback returns an edit that makes an authorization request's
// parameters one from loopback, with redirectURI.
func asLoopback(redirectURI string) func(url.Values) {
	return func(v url.Values) {
		v.Set("client_id", "loopback")
		v.Set("redirect_uri", redirectURI)
		withPKCE(v)
	}
}

// REQ-NATIVE-1, REQ-BCP-3, REQ-OAUTH-12: a native app's authorization
// request may name a loopback IP redirect URI it registered with any port,
// as one listening on a port the operating system chose does. The response
// is redirected to the URI as requested, port included, and the code is
// redeemed for that URI alone.
func TestLoopbackRedirectURIAnyPort(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	tests := []struct {
		name      string
		requested string
		otherPort string // the requested URI with another port, which the code must not be redeemed for
	}{
		{name: "as registered, without a port", requested: loopbackRedirectURI, otherPort: "http://127.0.0.1:49152/callback"},
		{name: "ephemeral port", requested: "http://127.0.0.1:49152/callback", otherPort: loopbackRedirectURI},
		{name: "lowest port", requested: "http://127.0.0.1:1/callback", otherPort: "http://127.0.0.1:2/callback"},
		{name: "highest port", requested: "http://127.0.0.1:65535/callback", otherPort: "http://127.0.0.1:65534/callback"},
		{name: "IPv6, as registered, with a port", requested: loopbackIPv6RedirectURI, otherPort: "http://[::1]:8001/v6/callback"},
		{name: "IPv6, another port", requested: "http://[::1]:51004/v6/callback", otherPort: loopbackIPv6RedirectURI},
		{name: "IPv6, without a port", requested: "http://[::1]/v6/callback", otherPort: loopbackIPv6RedirectURI},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			params := clientParams("loopback", tt.requested)
			withPKCE(params)
			b := &browser{t: t, handler: handler}
			u := location(t, b.decide(b.signIn(b.authorize(http.MethodGet, params)), "allow"))
			if got := withoutQuery(u); got != tt.requested {
				t.Fatalf("authorization response redirected to %q, want %q", got, tt.requested)
			}
			issued := u.Query().Get("code")
			if issued == "" {
				t.Fatalf("authorization response %q has no code", u)
			}

			// A code is used up by a failed redemption too, so the one for
			// another port is tried on a second code.
			other := pkceClient{clientID: "loopback", redirectURI: tt.otherPort}
			if got := tokenErrorCode(t, other.redeem(t, handler, other.form(code(t, handler, params), pkceVerifier)), http.StatusBadRequest); got != "invalid_grant" {
				t.Errorf("POST %s with redirect_uri %q for a code issued for %q error = %q, want %q", tokenPath, tt.otherPort, tt.requested, got, "invalid_grant")
			}

			client := pkceClient{clientID: "loopback", redirectURI: tt.requested}
			if got := idTokenAudience(t, handler, client.redeem(t, handler, client.form(issued, pkceVerifier))); got != "loopback" {
				t.Errorf("POST %s with redirect_uri %q ID token aud = %v, want %q", tokenPath, tt.requested, got, "loopback")
			}
		})
	}
}
