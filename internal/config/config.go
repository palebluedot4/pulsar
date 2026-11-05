// Package config loads pulsar's configuration from the environment.
package config

import (
	"errors"
	"fmt"

	"github.com/palebluedot4/pulsar/internal/oidc"
)

// Config is pulsar's runtime configuration.
type Config struct {
	// Addr is the TCP address the HTTP server listens on.
	Addr string

	// Issuer is the OP's Issuer Identifier.
	Issuer *oidc.Issuer

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

	issuer, err := oidc.ParseIssuer(getenv("PULSAR_ISSUER"))
	if err != nil {
		return Config{}, fmt.Errorf("PULSAR_ISSUER: %w", err)
	}
	cfg.Issuer = issuer

	switch {
	case cfg.TLSCertFile != "" && cfg.TLSKeyFile == "":
		return Config{}, errors.New("PULSAR_TLS_KEY is required when PULSAR_TLS_CERT is set")
	case cfg.TLSCertFile == "" && cfg.TLSKeyFile != "":
		return Config{}, errors.New("PULSAR_TLS_CERT is required when PULSAR_TLS_KEY is set")
	case cfg.TLSCertFile != "" && !issuer.HTTPS():
		// Otherwise every endpoint URL pulsar publishes would name a
		// scheme it does not serve.
		return Config{}, errors.New("PULSAR_ISSUER must use https when PULSAR_TLS_CERT is set")
	}
	return cfg, nil
}
