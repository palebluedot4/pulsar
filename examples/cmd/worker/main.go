// Command worker is the worker example, a job that calls the API example
// on its own behalf, with no End-User (package
// github.com/palebluedot4/pulsar/examples/worker).
//
// Usage:
//
//	worker [flags]
//
// Each run gets an access token by the client credentials grant, records
// a note in the API saying when it ran, and prints the worker's notes.
// Each flag defaults to an environment variable: -issuer to ISSUER,
// -client-id to WORKER_CLIENT_ID, -key to WORKER_KEY_FILE, -resource to
// API_IDENTIFIER, and -api to API_URL.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/oauth2"

	"github.com/palebluedot4/pulsar/examples/api"
	"github.com/palebluedot4/pulsar/examples/worker"
)

// runTimeout bounds a run, discovery and every request included.
const runTimeout = 30 * time.Second

func main() {
	issuer := flag.String("issuer", os.Getenv("ISSUER"), "pulsar's Issuer Identifier (ISSUER)")
	clientID := flag.String("client-id", envOr("WORKER_CLIENT_ID", "worker"), "the worker's client_id (WORKER_CLIENT_ID)")
	keyFile := flag.String("key", envOr("WORKER_KEY_FILE", "worker-key.json"), "the file of the worker's private key, a JWK (WORKER_KEY_FILE)")
	resource := flag.String("resource", os.Getenv("API_IDENTIFIER"), "the API's identifier, sent as the resource parameter (API_IDENTIFIER)")
	apiURL := flag.String("api", envOr("API_URL", "http://127.0.0.1:8081"), "the API's URL (API_URL)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: worker [flags]")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() > 0 {
		flag.Usage()
		os.Exit(2)
	}

	cfg := worker.Config{
		Issuer:   *issuer,
		ClientID: *clientID,
		Resource: *resource,
		Scopes:   []string{api.ScopeRead, api.ScopeWrite},
	}
	if err := run(cfg, *keyFile, *apiURL); err != nil {
		fmt.Fprintf(os.Stderr, "worker: %v\n", err)
		os.Exit(1)
	}
}

func run(cfg worker.Config, keyFile, apiURL string) error {
	if cfg.Issuer == "" || cfg.Resource == "" {
		return errors.New("-issuer and -resource are required")
	}
	data, err := os.ReadFile(keyFile) //nolint:gosec // G304: the operator's own flag.
	if err != nil {
		return err
	}
	if cfg.Key, err = worker.ParseKey(data); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()

	ts, err := worker.NewTokenSource(ctx, cfg)
	if err != nil {
		return err
	}
	// One token for the run, unless it expires.
	ts = oauth2.ReuseTokenSource(nil, ts)
	notes, err := worker.Run(ctx, ts, apiURL, "ran at "+time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return err
	}
	for _, n := range notes {
		fmt.Println(n)
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
