package oidc

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"strings"
)

// Issuer is the OP's Issuer Identifier. One made by [ParseIssuer] has no
// terminating slash, so every endpoint URL is the issuer followed by the
// endpoint's path, and the discovery document's path is the issuer's path
// followed by /.well-known/openid-configuration.
type Issuer struct {
	url *url.URL
}

// ParseIssuer checks raw against OpenID Connect Discovery 1.0 §3: a URL
// using the https scheme with no query or fragment components. http is
// allowed on a loopback host, so that pulsar can run locally without a
// certificate.
//
// The issuer is compared as a string (Discovery §4.3), so raw must also be
// in the one form every Client derives the same way: the form url.URL
// prints, with a lowercase host, no empty or default port, and a clean path
// without a terminating slash.
func ParseIssuer(raw string) (*Issuer, error) {
	if raw == "" {
		return nil, errors.New("required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		// The inner error, because url.Error quotes the whole value,
		// which may hold credentials.
		if ue, ok := errors.AsType[*url.Error](err); ok {
			err = ue.Err
		}
		return nil, fmt.Errorf("not a URL: %w", err)
	}
	if u.User != nil {
		// The value is not quoted, since it holds credentials.
		return nil, errors.New("must not contain a user name or password")
	}
	switch {
	case !u.IsAbs() || u.Host == "":
		return nil, fmt.Errorf("%q is not an absolute URL", raw)
	case u.Scheme != "https" && (u.Scheme != "http" || !isLoopback(u.Hostname())):
		return nil, fmt.Errorf("%q must use https, or http on a loopback host", raw)
	// The raw value is checked, because url.Parse does not record an empty
	// fragment ("https://op.example#") at all.
	case strings.Contains(raw, "?"):
		return nil, fmt.Errorf("%q must not have a query", raw)
	case strings.Contains(raw, "#"):
		return nil, fmt.Errorf("%q must not have a fragment", raw)
	case u.Host != strings.ToLower(u.Host):
		return nil, fmt.Errorf("%q must have a lowercase host", raw)
	case strings.HasSuffix(u.Host, ":") || u.Port() == defaultPort[u.Scheme]:
		return nil, fmt.Errorf("%q must not have an empty or default port", raw)
	case strings.HasSuffix(u.Path, "/"):
		return nil, fmt.Errorf("%q must not end with /", raw)
	case u.Path != "" && path.Clean(u.Path) != u.Path:
		return nil, fmt.Errorf("%q must have a path without empty, . or .. segments", raw)
	}
	if s := u.String(); s != raw {
		return nil, fmt.Errorf("%q is not in canonical form; use %q", raw, s)
	}
	return &Issuer{url: u}, nil
}

// defaultPort is the port each allowed scheme implies.
var defaultPort = map[string]string{"https": "443", "http": "80"}

// isLoopback reports whether host names the loopback interface.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// String returns the Issuer Identifier exactly as configured.
func (i *Issuer) String() string {
	return i.url.String()
}

// endpointURL returns the URL of the endpoint at path p under the issuer.
func (i *Issuer) endpointURL(p string) string {
	return i.url.String() + p
}

// route returns the request path at which the endpoint at path p is served.
func (i *Issuer) route(p string) string {
	return i.url.EscapedPath() + p
}

// HTTPS reports whether the issuer uses the https scheme rather than the
// http allowed on a loopback host.
func (i *Issuer) HTTPS() bool {
	return i.url.Scheme == "https"
}
