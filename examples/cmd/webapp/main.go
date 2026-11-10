// Command webapp serves the web app example, a confidential Client that
// keeps the End-User's tokens on the server and calls the API example
// (package github.com/palebluedot4/pulsar/examples/webapp).
//
// Usage:
//
//	WEBAPP_CLIENT_SECRET=... webapp -issuer http://localhost:8080 -resource https://api.example/notes
//
// Each flag defaults to an environment variable: -issuer to ISSUER,
// -client-id to WEBAPP_CLIENT_ID, -url to WEBAPP_URL, -addr to
// WEBAPP_ADDR, -resource to API_IDENTIFIER, and -api to API_URL. The
// client secret is read from WEBAPP_CLIENT_SECRET alone, so that it is not
// in the command line other users of the system can see.
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

	"github.com/palebluedot4/pulsar/examples/webapp"
)

func main() {
	issuer := flag.String("issuer", os.Getenv("ISSUER"), "pulsar's Issuer Identifier (ISSUER)")
	clientID := flag.String("client-id", envOr("WEBAPP_CLIENT_ID", "webapp"), "the web app's client_id (WEBAPP_CLIENT_ID)")
	appURL := flag.String("url", envOr("WEBAPP_URL", "http://localhost:8082"), "the web app's URL, under which its redirect URIs are registered (WEBAPP_URL)")
	addr := flag.String("addr", envOr("WEBAPP_ADDR", "localhost:8082"), "the address to listen on (WEBAPP_ADDR)")
	resource := flag.String("resource", os.Getenv("API_IDENTIFIER"), "the API's identifier, sent as the resource parameter (API_IDENTIFIER)")
	apiURL := flag.String("api", envOr("API_URL", "http://127.0.0.1:8081"), "the API's URL (API_URL)")
	flag.Parse()

	cfg := webapp.Config{
		Issuer:        *issuer,
		ClientID:      *clientID,
		ClientSecret:  os.Getenv("WEBAPP_CLIENT_SECRET"),
		URL:           *appURL,
		APIURL:        *apiURL,
		APIIdentifier: *resource,
		HTTPClient:    &http.Client{Timeout: 30 * time.Second},
	}
	if err := run(cfg, *addr); err != nil {
		fmt.Fprintf(os.Stderr, "webapp: %v\n", err)
		os.Exit(1)
	}
}

func run(cfg webapp.Config, addr string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	handler, err := webapp.New(ctx, cfg)
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	// ListenAndServe returns as soon as Shutdown begins, so run waits for
	// Shutdown to finish the requests in flight before it returns.
	shutdown := make(chan error, 1)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		shutdown <- srv.Shutdown(shutdownCtx)
	}()
	log.Printf("serving %q for %q on %q", cfg.URL, cfg.Issuer, addr)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return <-shutdown
}

// envOr returns the environment variable key, or def if it is unset.
func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}
