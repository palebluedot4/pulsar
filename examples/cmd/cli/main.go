// Command cli is the CLI example, a public Client that signs the End-User
// in through their browser and a loopback redirect, and calls the API
// example (package github.com/palebluedot4/pulsar/examples/cli).
//
// Usage:
//
//	cli [flags] list        lists the End-User's notes
//	cli [flags] add TEXT    adds a note
//
// Each run signs in again, asking only for the scope its command needs:
// notes:read to list, notes:write to add. Each flag defaults to an
// environment variable: -issuer to ISSUER, -client-id to CLI_CLIENT_ID,
// -resource to API_IDENTIFIER, and -api to API_URL.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/palebluedot4/pulsar/examples/api"
	"github.com/palebluedot4/pulsar/examples/cli"
)

// signInTimeout bounds how long the CLI waits for the End-User to sign in.
const signInTimeout = 5 * time.Minute

func main() {
	issuer := flag.String("issuer", os.Getenv("ISSUER"), "pulsar's Issuer Identifier (ISSUER)")
	clientID := flag.String("client-id", envOr("CLI_CLIENT_ID", "cli"), "the CLI's client_id (CLI_CLIENT_ID)")
	resource := flag.String("resource", os.Getenv("API_IDENTIFIER"), "the API's identifier, sent as the resource parameter (API_IDENTIFIER)")
	apiURL := flag.String("api", envOr("API_URL", "http://127.0.0.1:8081"), "the API's URL (API_URL)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: cli [flags] list | add TEXT")
		flag.PrintDefaults()
	}
	flag.Parse()

	cfg := cli.Config{Issuer: *issuer, ClientID: *clientID, Resource: *resource, OpenBrowser: openBrowser}
	if err := run(cfg, *apiURL, flag.Args()); err != nil {
		fmt.Fprintf(os.Stderr, "cli: %v\n", err)
		os.Exit(1)
	}
}

func run(cfg cli.Config, apiURL string, args []string) error {
	var text string // the note to add; "" to list
	switch {
	case len(args) == 1 && args[0] == "list":
		cfg.Scopes = []string{api.ScopeRead}
	case len(args) >= 2 && args[0] == "add":
		cfg.Scopes, text = []string{api.ScopeWrite}, strings.Join(args[1:], " ")
	default:
		flag.Usage()
		return errors.New("unknown command")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, signInTimeout)
	defer cancel()

	session, err := cli.SignIn(ctx, cfg)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "signed in as %s\n", session.Subject)

	if text != "" {
		return cli.AddNote(ctx, apiURL, session.AccessToken, text)
	}
	notes, err := cli.ListNotes(ctx, apiURL, session.AccessToken)
	if err != nil {
		return err
	}
	for _, n := range notes {
		fmt.Println(n)
	}
	return nil
}

// openBrowser opens url in the system browser, as RFC 8252 §6 says a
// native app should, rather than in a view the app controls. It also
// prints url, for a system without one.
func openBrowser(ctx context.Context, url string) error {
	fmt.Fprintf(os.Stderr, "Sign in at:\n\n  %s\n\n", url)
	name, args := "xdg-open", []string{url}
	switch runtime.GOOS {
	case "darwin":
		name = "open"
	case "windows":
		name, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	}
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: a fixed opener, given the URL the CLI built as one argument, never through a shell.
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Could not open a browser (%v); open the URL above yourself.\n", err)
		return nil
	}
	go func() { _ = cmd.Wait() }() // The opener exits once the browser has the URL.
	return nil
}

// envOr returns the environment variable key, or def if it is unset.
func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}
