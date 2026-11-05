// Pulsar is an OpenID Provider.
//
// It serves HTTP until it receives an interrupt or SIGTERM, then shuts down
// gracefully.
//
// Configuration is read from the environment:
//
//	PULSAR_ADDR	address to listen on (default ":8080")
//	PULSAR_ISSUER	the Issuer Identifier, an https URL; http only on a loopback host (required)
//	PULSAR_TLS_CERT	PEM certificate chain to serve TLS with (with PULSAR_TLS_KEY)
//	PULSAR_TLS_KEY	PEM private key for PULSAR_TLS_CERT
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
	"syscall"
	"time"

	"github.com/palebluedot4/pulsar/internal/config"
	"github.com/palebluedot4/pulsar/internal/server"
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

// run starts the server and blocks until ctx is canceled or a signal
// arrives. Its parameters stand in for the process environment so that tests
// can drive the whole program.
func run(ctx context.Context, _ []string, getenv func(string) string, _ io.Reader, stdout, _ io.Writer) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load(getenv)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	logger := slog.New(slog.NewJSONHandler(stdout, nil))

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

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	srv := &http.Server{
		Handler:           server.New(cfg.Issuer),
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

	select {
	case err := <-serveErr:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}

	logger.InfoContext(ctx, "shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
