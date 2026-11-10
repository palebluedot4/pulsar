// Command api serves the API example, a Resource Server that verifies
// pulsar's access tokens itself (package
// github.com/palebluedot4/pulsar/examples/api).
//
// Usage:
//
//	api -issuer http://127.0.0.1:9080 -identifier https://api.example/notes -addr 127.0.0.1:8081
//
// Each flag defaults to an environment variable: ISSUER, API_IDENTIFIER
// and API_ADDR.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/palebluedot4/pulsar/examples/api"
)

func main() {
	issuer := flag.String("issuer", os.Getenv("ISSUER"), "pulsar's Issuer Identifier (ISSUER)")
	identifier := flag.String("identifier", os.Getenv("API_IDENTIFIER"), "the API's identifier, as pulsar's registry lists it (API_IDENTIFIER)")
	addr := flag.String("addr", envOr("API_ADDR", "127.0.0.1:8081"), "the address to listen on (API_ADDR)")
	flag.Parse()

	if err := run(*issuer, *identifier, *addr); err != nil {
		fmt.Fprintf(os.Stderr, "api: %v\n", err)
		os.Exit(1)
	}
}

func run(issuer, identifier, addr string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	handler, err := api.New(ctx, api.Config{Issuer: issuer, Identifier: identifier})
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	log.Printf("serving %q for %q on %q", identifier, issuer, addr) //nolint:gosec // G706: the operator's own flags, quoted.
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// envOr returns the environment variable key, or def if it is unset.
func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}
