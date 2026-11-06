// Package config loads pulsar's configuration from the environment.
//
// The database connection is also shaped by settings pulsar does not read
// itself: pgx, like libpq, takes anything PULSAR_DATABASE_URL leaves out
// from the process's PG* environment variables (PGHOST, PGUSER, PGPASSWORD,
// PGSSLMODE and the rest), from the service file a PGSERVICE names, and
// a password from the password file.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"

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

	// Secret is the key from which pulsar derives the key that encrypts
	// its signing keys at rest.
	Secret Secret

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

	secret, err := parseSecret(getenv("PULSAR_SECRET"))
	if err != nil {
		return Config{}, err
	}
	cfg.Secret = secret
	return cfg, nil
}

// SecretSize is the size of PULSAR_SECRET, in bytes, once decoded.
const SecretSize = 32

// Secret is the decoded PULSAR_SECRET. It prints, and encodes as JSON or
// text, as a placeholder, so that a Config printed or logged by mistake
// does not disclose it.
type Secret [SecretSize]byte

// redacted is what a Secret prints and encodes as.
const redacted = "[redacted]"

// Format writes the placeholder, whatever the verb.
func (Secret) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, redacted) // fmt reports no write error to its caller.
}

// MarshalText returns the placeholder, so that encoding/json and log/slog
// print it in place of the bytes.
func (Secret) MarshalText() ([]byte, error) {
	return []byte(redacted), nil
}

// parseSecret decodes PULSAR_SECRET: SecretSize bytes in the standard,
// padded base64 alphabet of RFC 4648 §4, as `openssl rand -base64 32`
// prints them. Its errors never include the value, nor where in it
// decoding failed.
func parseSecret(raw string) (Secret, error) {
	if raw == "" {
		return Secret{}, errors.New("PULSAR_SECRET is required: 32 random bytes in standard, padded base64, " +
			"such as `openssl rand -base64 32` prints")
	}
	b, err := base64.StdEncoding.Strict().DecodeString(raw)
	if err != nil || len(b) != SecretSize {
		return Secret{}, errors.New("PULSAR_SECRET must be 32 random bytes in standard, padded base64, " +
			"such as `openssl rand -base64 32` prints")
	}
	return Secret(b), nil
}
