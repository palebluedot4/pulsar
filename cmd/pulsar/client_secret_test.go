package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/palebluedot4/pulsar/internal/registry"
)

// REQ-OAUTH-44: `pulsar client-secret`, with no configuration at all,
// prints one line, a JSON object of a Client secret and its
// client_secret_hash; a registry file with that hash authenticates the
// Client by that secret. That the secret is 256 bits from crypto/rand is
// internal/registry's to test.
func TestRunClientSecret(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	noEnv := func(string) string { return "" }
	if err := run(t.Context(), []string{"pulsar", "client-secret"}, noEnv, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("run(client-secret) = %v, want nil", err)
	}
	line, ok := strings.CutSuffix(out.String(), "\n")
	if !ok || strings.Contains(line, "\n") {
		t.Fatalf("run(client-secret) printed %q, want one line", out.String())
	}
	var printed struct {
		Secret string `json:"client_secret"`
		Hash   string `json:"client_secret_hash"`
	}
	dec := json.NewDecoder(strings.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&printed); err != nil {
		t.Fatalf("run(client-secret) printed %q, not a JSON object of client_secret and client_secret_hash: %v", line, err)
	}

	reg, err := registry.Parse([]byte(registryJSON(t, []entry{with(secretClient(), "client_secret_hash", printed.Hash)}, nil)))
	if err != nil {
		t.Fatalf("registry.Parse with the printed client_secret_hash = %v, want nil", err)
	}
	if _, ok, err := reg.AuthenticateClientSecret(t.Context(), registry.ClientSecretBasic, "rp", printed.Secret); !ok || err != nil {
		t.Errorf("AuthenticateClientSecret(rp, printed client_secret) = %v, %v; want true, nil", ok, err)
	}
}
