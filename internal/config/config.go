// Package config loads pulsar's configuration from the environment.
//
// The database connection is also shaped by settings pulsar does not read
// itself: pgx, like libpq, takes anything PULSAR_DATABASE_URL leaves out
// from the process's PG* environment variables (PGHOST, PGUSER, PGPASSWORD,
// PGSSLMODE and the rest), from the service file a PGSERVICE names, and
// a password from the password file.
package config

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palebluedot4/pulsar/internal/oidc"
)

// Config is pulsar's runtime configuration.
type Config struct {
	// Addr is the TCP address the HTTP server listens on.
	Addr string

	// Issuer is the OP's Issuer Identifier.
	Issuer *oidc.Issuer

	// DatabaseURL is the PostgreSQL connection string, as a URL or in
	// keyword/value form, with any pgxpool settings.
	DatabaseURL string

	// TLSCertFile and TLSKeyFile name a PEM certificate chain and its
	// private key. Both are set, and pulsar serves TLS itself, or neither.
	TLSCertFile string
	TLSKeyFile  string
}

// Load reads the configuration through getenv, which has the signature of
// [os.Getenv] so that tests can supply their own environment. Its errors
// name the setting at fault.
func Load(getenv func(string) string) (Config, error) {
	cfg := Config{
		Addr:        ":8080",
		DatabaseURL: getenv("PULSAR_DATABASE_URL"),
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

	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("PULSAR_DATABASE_URL is required")
	}
	// The pool parses the same string again when it opens; parsing it here
	// makes a malformed one a configuration error. pgx's error quotes the
	// string, and pgx documents its password redaction as best effort, so
	// the error is not passed on. pgx also reads libpq's PG* variables and
	// service file from the process environment, not through getenv, and
	// a bad one fails here too, so the error names them as well.
	if _, err := pgxpool.ParseConfig(cfg.DatabaseURL); err != nil {
		return Config{}, errors.New("PULSAR_DATABASE_URL is not a valid PostgreSQL connection string, " +
			"or a PG* environment variable or service file that pgx reads with it is invalid")
	}
	return cfg, nil
}
