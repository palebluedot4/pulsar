package oidc

import (
	"net/http"
	"slices"

	"github.com/palebluedot4/pulsar/internal/registry"
)

// corsMaxAge is how long, in seconds, a browser may cache the result of a
// preflight: an hour, as node-oidc-provider and Keycloak have it. Browsers
// may impose a lower limit (Fetch, "HTTP responses").
const corsMaxAge = "3600"

// corsPolicy is how an endpoint answers the cross-origin requests of
// browser-based Clients, through the CORS protocol of the Fetch standard
// (RFC 10017 §6.3.3.4). A Client may send requests from the origins of its
// redirect URIs, if allows says it may send any.
//
// A preflight carries an origin and no Client, so it is approved for an
// origin that some Client may send requests from; the actual request is
// then checked against its own Client, once the endpoint knows it, as RFC
// 10017 §6.3.3.4 describes. A response to a request from an origin not
// allowed, or before the Client is known, has no CORS headers, so the
// browser withholds it from the application. No response allows
// credentials: these endpoints use no cookies.
type corsPolicy struct {
	allow         string // Allow: the endpoint's methods (RFC 9110 §10.2.1)
	allowMethods  string // Access-Control-Allow-Methods
	allowHeaders  string // Access-Control-Allow-Headers, or "" for none
	exposeHeaders string // Access-Control-Expose-Headers, or "" for none
	// refusal describes the error that answers a request from an origin
	// not allowed.
	refusal string
	allows  func(*registry.Client) bool
	// known holds the origins a preflight is approved for.
	known map[string]bool
}

// newCORSPolicy returns the policy p, with its known origins: those of the
// Clients of reg that p allows.
func newCORSPolicy(reg *registry.Registry, p corsPolicy) *corsPolicy {
	p.known = make(map[string]bool)
	for c := range reg.Clients() {
		if p.allows(c) {
			for _, o := range c.Origins {
				p.known[o] = true
			}
		}
	}
	return &p
}

// requestOrigin returns the origin in r's Origin header, and whether r
// has one. A browser sends one with every cross-origin request, and with
// a POST from the same origin too; a Client that is not a browser sends
// none (Fetch, "Origin header"). A request with more than one returns "",
// which no Client's origins hold, so that it is refused as one from an
// origin not allowed. pulsar serves no page that sends requests to these
// endpoints, so a same-origin request is refused too, unless its origin
// is that of a Client's redirect URI.
func requestOrigin(r *http.Request) (origin string, sent bool) {
	values := r.Header.Values("Origin")
	switch len(values) {
	case 0:
		return "", false
	case 1:
		return values[0], true
	default:
		return "", true
	}
}

// handlePreflight answers an OPTIONS request, with the endpoint's methods.
// A preflight, which names the method of the request it precedes, from a
// known origin is approved: with the origin, the methods and request
// headers the endpoint takes, and how long the browser may cache the
// result (Fetch, "HTTP responses"). Any other gets no CORS headers, so
// the browser does not send the request.
func (p *corsPolicy) handlePreflight() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Allow", p.allow)
		h.Add("Vary", "Origin")
		origin, _ := requestOrigin(r)
		if r.Header.Get("Access-Control-Request-Method") != "" && p.known[origin] {
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Methods", p.allowMethods)
			if p.allowHeaders != "" {
				h.Set("Access-Control-Allow-Headers", p.allowHeaders)
			}
			h.Set("Access-Control-Max-Age", corsMaxAge)
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// check reports whether r, an actual request whose Client is client, or
// nil if no Client is known, may be answered: it was not sent from a
// browser, or was sent from one of the origins client may send requests
// from. If it was, the response's headers let the application read it,
// and the headers of p's exposeHeaders. Every response varies by origin,
// so that a cache does not serve one to another (Fetch, "CORS protocol
// and HTTP caches"); the handler sets Vary before calling check.
func (p *corsPolicy) check(w http.ResponseWriter, r *http.Request, client *registry.Client) bool {
	origin, sent := requestOrigin(r)
	if !sent {
		return true
	}
	if client == nil || !p.allows(client) || !slices.Contains(client.Origins, origin) {
		return false
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	if p.exposeHeaders != "" {
		h.Set("Access-Control-Expose-Headers", p.exposeHeaders)
	}
	return true
}

// HandleTokenPreflight answers OPTIONS requests at the token endpoint,
// approving preflights from the origins of public Clients.
func (p *Provider) HandleTokenPreflight() http.Handler {
	return p.tokenCORS.handlePreflight()
}

// HandleUserInfoPreflight answers OPTIONS requests at the UserInfo
// endpoint, approving preflights from the origins of every Client.
func (p *Provider) HandleUserInfoPreflight() http.Handler {
	return p.userInfoCORS.handlePreflight()
}
