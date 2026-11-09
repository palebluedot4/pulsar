package main

import (
	"bytes"
	"encoding/json/v2"
	"io"
	"strings"
	"testing"

	"github.com/palebluedot4/pulsar/internal/registry"
)

// runClientSecret runs pulsar with args after the program name and an
// empty environment, and returns what it printed and run's result.
func runClientSecret(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	noEnv := func(string) string { return "" }
	err := run(t.Context(), append([]string{"pulsar"}, args...), noEnv, strings.NewReader(""), &out, io.Discard)
	return out.String(), err
}

// REQ-OAUTH-44: `pulsar client-secret`, with no configuration at all,
// prints one line, a JSON object of exactly a Client secret and its
// client_secret_hash; a registry file with that hash authenticates the
// Client by that secret. That the secret is 256 bits from crypto/rand is
// internal/registry's to test.
func TestRunClientSecret(t *testing.T) {
	t.Parallel()

	out, err := runClientSecret(t, "client-secret")
	if err != nil {
		t.Fatalf("run(client-secret) = %v, want nil", err)
	}
	line, ok := strings.CutSuffix(out, "\n")
	if !ok || strings.Contains(line, "\n") {
		t.Fatalf("run(client-secret) printed %q, want one line", out)
	}
	var printed struct {
		Secret string `json:"client_secret"`
		Hash   string `json:"client_secret_hash"`
	}
	// Strictly, as the registry file is decoded: no other member, none
	// twice or in another case, and nothing after the object.
	if err := json.Unmarshal([]byte(line), &printed, json.RejectUnknownMembers(true)); err != nil {
		t.Fatalf("run(client-secret) printed %q, not a JSON object of client_secret and client_secret_hash: %v", line, err)
	}

	reg, err := registry.Parse([]byte(registryJSON(t, []entry{with(secretClient(), "client_secret_hash", printed.Hash)}, nil)))
	if err != nil {
		t.Fatalf("registry.Parse(a registry with the printed client_secret_hash) = %v, want nil", err)
	}
	if _, ok, err := reg.AuthenticateClientSecret(t.Context(), registry.ClientSecretBasic, "rp", printed.Secret); !ok || err != nil {
		t.Errorf("AuthenticateClientSecret(rp, printed client_secret) = %v, %v; want true, nil", ok, err)
	}
}

// `pulsar client-secret` takes no argument, and prints nothing when
// given one.
func TestRunClientSecretRefusesArgument(t *testing.T) {
	t.Parallel()

	out, err := runClientSecret(t, "client-secret", "rp")
	const want = `unknown command "client-secret rp"`
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("run(client-secret rp) = %v, want an error containing %q", err, want)
	}
	if out != "" {
		t.Errorf("run(client-secret rp) printed %q, want nothing", out)
	}
}
