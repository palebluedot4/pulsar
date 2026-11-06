// Pulsar is an OpenID Provider.
//
// It reads its Clients and End-Users from the registry file, and refuses
// to start if the file is invalid. It serves HTTP from the start, and
// meanwhile applies any pending database migrations, holding a lock so
// that replicas starting together migrate once, and then loads its signing
// keys, generating the first if there is none. /readyz and the JWK Set
// answer 503 until both are done, and pulsar exits if either fails. It
// then reloads the signing keys once a minute, and serves until it
// receives an interrupt or SIGTERM, when it shuts down gracefully.
//
// Usage:
//
//	pulsar
//	pulsar keys rotate
//
// `pulsar keys rotate` stores a new signing key and exits. Every replica
// publishes the key in its JWK Set at its next reload, and signs with it
// from two minutes after it is stored: one reload interval plus the JWK
// Set's cache lifetime, so that every replica and every cached JWK Set
// has it first. The key it replaces stays in the JWK Set until every
// token it signed has expired. The command reads the same environment as
// the server, and refuses a database pulsar has never started against.
//
// Configuration is read from the environment:
//
//	PULSAR_ADDR		address to listen on (default ":8080")
//	PULSAR_ISSUER		the Issuer Identifier, an https URL; http only on a loopback host (required)
//	PULSAR_DATABASE_URL	PostgreSQL connection string (required)
//	PULSAR_SECRET		32 random bytes in standard, padded base64, e.g. from `openssl rand -base64 32`,
//				from which the key encrypting the stored signing keys is derived; every
//				start against a database needs the same value (required)
//	PULSAR_REGISTRY		path of the registry file listing the Clients and End-Users (required)
//	PULSAR_TLS_CERT		PEM certificate chain to serve TLS with (with PULSAR_TLS_KEY)
//	PULSAR_TLS_KEY		PEM private key for PULSAR_TLS_CERT
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palebluedot4/pulsar/internal/config"
	"github.com/palebluedot4/pulsar/internal/postgres"
	"github.com/palebluedot4/pulsar/internal/registry"
	"github.com/palebluedot4/pulsar/internal/server"
	"github.com/palebluedot4/pulsar/internal/signing"
)

// Server timeouts. Without them a slow or stalled client holds a connection,
// and its goroutine, indefinitely.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 120 * time.Second
)

// shutdownTimeout bounds how long in-flight requests may take to finish once
// shutdown begins.
const shutdownTimeout = 10 * time.Second

func main() {
	ctx := context.Background()
	if err := run(ctx, os.Args, os.Getenv, os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "pulsar: %v\n", err)
		os.Exit(1)
	}
}

// usage is the command line pulsar accepts.
const usage = "usage: pulsar [keys rotate]"

// run runs the command that args name: with none, it starts the server
// and blocks until ctx is canceled or a signal arrives. Its parameters
// stand in for the process environment so that tests can drive the whole
// program.
func run(ctx context.Context, args []string, getenv func(string) string, _ io.Reader, stdout, _ io.Writer) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	var command string
	if len(args) > 1 {
		command = strings.Join(args[1:], " ")
	}
	if command != "" && command != "keys rotate" {
		return fmt.Errorf("unknown command %q; %s", command, usage)
	}

	cfg, err := config.Load(getenv)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	logger := slog.New(slog.NewJSONHandler(stdout, nil))
	if command == "keys rotate" {
		return rotateKeys(ctx, cfg, logger)
	}

	// The registry and the certificate are loaded before the database is
	// touched, so that a local mistake is reported as such rather than
	// after a connection.
	reg, err := registry.Load(cfg.RegistryFile)
	if err != nil {
		return fmt.Errorf("load the registry at PULSAR_REGISTRY: %w", err)
	}
	var tlsConfig *tls.Config
	if cfg.TLSCertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("load PULSAR_TLS_CERT and PULSAR_TLS_KEY: %w", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	// Errors name the setting, so an operator knows where to look. pgx's
	// connection errors give the user, database and host, never the
	// password; config.Load has already parsed the string, so pgxpool.New
	// cannot fail with a parse error that would quote it. The pool
	// connects only when first used.
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("open the database at PULSAR_DATABASE_URL: %w", err)
	}

	keys := signing.New(pool, cfg.Secret)

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.Addr)
	if err != nil {
		pool.Close()
		return fmt.Errorf("listen: %w", err)
	}
	// pulsar serves before it migrates, which may wait minutes for another
	// replica's lock: /livez answers meanwhile, and /readyz answers 503
	// until ready is closed, once the signing keys are loaded too.
	ready := make(chan struct{})
	srv := &http.Server{
		Handler:           server.New(logger, cfg.Issuer, pool, keys, reg, ready),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}

	serveErr := make(chan error, 1)
	go func() {
		if tlsConfig != nil {
			// The certificate is already in srv.TLSConfig.
			serveErr <- srv.ServeTLS(ln, "", "")
			return
		}
		serveErr <- srv.Serve(ln)
	}()
	logger.InfoContext(ctx, "listening", "addr", ln.Addr().String(), "tls", tlsConfig != nil)

	// Migrate and load the signing keys, report the result on startErr,
	// and then, if both succeeded, reload the keys until the run ends.
	keysCtx, stopKeys := context.WithCancel(ctx)
	defer stopKeys()
	startErr := make(chan error, 1)
	keysDone := make(chan struct{})
	go func() {
		defer close(keysDone)
		err := prepare(keysCtx, pool, keys, logger)
		startErr <- err
		if err == nil {
			close(ready)
			keys.Run(keysCtx, logger)
		}
	}()

	// Serve until a signal, a failed start or a failed server. A start
	// that fails because a signal canceled it is a graceful exit, as a
	// signal while serving is.
	var runErr error
	serving := true
wait:
	for {
		select {
		case err := <-serveErr:
			serving = false
			runErr = fmt.Errorf("serve: %w", err)
			break wait
		case err := <-startErr:
			startErr = nil // Received; a nil channel is never ready again.
			if err != nil && ctx.Err() == nil {
				runErr = err
				break wait
			}
		case <-ctx.Done():
			break wait
		}
	}
	stopKeys()
	if startErr != nil {
		// The run is already ending for another reason; only a failure
		// that is not the cancellation itself is worth reporting with it.
		if err := <-startErr; err != nil && ctx.Err() == nil && !errors.Is(err, context.Canceled) {
			runErr = errors.Join(runErr, err)
		}
	}
	// Wait until migrating, loading or reloading has stopped and released
	// its connection.
	<-keysDone

	if serving {
		logger.InfoContext(ctx, "shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			// Handlers still running may hold pooled connections, and
			// pool.Close would wait for them; the process's exit closes
			// them instead.
			return errors.Join(runErr, fmt.Errorf("shutdown: %w", err))
		}
		if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
			runErr = errors.Join(runErr, fmt.Errorf("serve: %w", err))
		}
	}
	pool.Close()
	return runErr
}

// rotateKeys stores a new signing key, which serving replicas publish at
// their next reload and sign with once signing.ActivationDelay has passed,
// and reports its kid and when it starts signing.
func rotateKeys(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("open the database at PULSAR_DATABASE_URL: %w", err)
	}
	defer pool.Close()
	rotated, err := signing.New(pool, cfg.Secret).Rotate(ctx)
	if err != nil {
		return fmt.Errorf("rotate the signing key: %w", err)
	}
	logger.InfoContext(ctx, "signing key stored", "kid", rotated.KID, "signs_from", rotated.SignsFrom)
	return nil
}

// prepare migrates the database and then loads the signing keys,
// generating the first one if there is none. A failure of either ends the
// run, as a failed migration always has: a replica that cannot serve
// tokens must not stay up looking healthy to its liveness probe.
func prepare(ctx context.Context, pool *pgxpool.Pool, keys *signing.KeySet, logger *slog.Logger) error {
	applied, err := postgres.Migrate(ctx, pool)
	if err != nil {
		return fmt.Errorf("migrate the database at PULSAR_DATABASE_URL: %w", err)
	}
	logger.InfoContext(ctx, "migrated", "applied", applied)
	if err := keys.Load(ctx); err != nil {
		return fmt.Errorf("load the signing keys: %w", err)
	}
	active, _ := keys.Active() // Load has succeeded, so Active cannot fail.
	logger.InfoContext(ctx, "signing keys loaded", "kid", active.KID)
	return nil
}
