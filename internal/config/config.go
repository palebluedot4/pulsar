// Package config loads pulsar's configuration from the environment.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Config is pulsar's runtime configuration.
type Config struct {
	// Addr is the TCP address the HTTP server listens on.
	Addr string

	// Issuer is the OP's Issuer Identifier. Its String method returns
	// exactly the value the operator configured.
	Issuer *url.URL

	// TLSCertFile and TLSKeyFile name a PEM certificate chain and its
	// private key. Both are set, and pulsar serves TLS itself, or neither.
	TLSCertFile string
	TLSKeyFile  string
}

// Load reads the configuration through getenv, which has the signature of
// [os.Getenv] so that tests can supply their own environment.
func Load(getenv func(string) string) (Config, error) {
	cfg := Config{
		Addr:        ":8080",
		TLSCertFile: getenv("PULSAR_TLS_CERT"),
		TLSKeyFile:  getenv("PULSAR_TLS_KEY"),
	}
	if v := getenv("PULSAR_ADDR"); v != "" {
		cfg.Addr = v
	}

	issuer, err := parseIssuer(getenv("PULSAR_ISSUER"))
	if err != nil {
		return Config{}, fmt.Errorf("PULSAR_ISSUER: %w", err)
	}
	cfg.Issuer = issuer

	switch {
	case cfg.TLSCertFile != "" && cfg.TLSKeyFile == "":
		return Config{}, errors.New("PULSAR_TLS_KEY is required when PULSAR_TLS_CERT is set")
	case cfg.TLSCertFile == "" && cfg.TLSKeyFile != "":
		return Config{}, errors.New("PULSAR_TLS_CERT is required when PULSAR_TLS_KEY is set")
	case cfg.TLSCertFile != "" && issuer.Scheme != "https":
		// Otherwise every endpoint URL pulsar publishes would name a
		// scheme it does not serve.
		return Config{}, errors.New("PULSAR_ISSUER must use https when PULSAR_TLS_CERT is set")
	}
	return cfg, nil
}

// parseIssuer checks raw against OpenID Connect Discovery 1.0 §3: a URL
// using the https scheme with no query or fragment components. http is
// allowed on a loopback host, so that pulsar can run locally without a
// certificate.
func parseIssuer(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
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
	// Without a terminating slash, the issuer is exactly the discovery URL
	// minus /.well-known/openid-configuration, which is how Clients
	// derive it.
	case strings.HasSuffix(u.Path, "/"):
		return nil, fmt.Errorf("%q must not end with /", raw)
	}
	// The issuer is compared as a string (Discovery §4.3), so the value
	// pulsar publishes must be the one configured, character for character.
	if s := u.String(); s != raw {
		return nil, fmt.Errorf("%q is not in canonical form; use %q", raw, s)
	}
	return u, nil
}

// isLoopback reports whether host names the loopback interface.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
