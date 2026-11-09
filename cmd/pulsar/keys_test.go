package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
)

// runCommand runs pulsar with args after the program name and env,
// completed as start completes it, and returns its log lines and run's
// result.
func runCommand(t *testing.T, env map[string]string, args ...string) ([]logLine, error) {
	t.Helper()
	var out bytes.Buffer
	err := run(t.Context(), append([]string{"pulsar"}, args...), environment(env), strings.NewReader(""), &out, io.Discard)
	var lines []logLine
	sc := bufio.NewScanner(&out)
	for sc.Scan() {
		var line logLine
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatalf("log line %q is not JSON: %v", sc.Bytes(), err)
		}
		lines = append(lines, line)
	}
	return lines, err
}

// kids returns the kid of each key in set, sorted.
func kids(set jwkSet) []string {
	var kids []string
	for _, key := range set.Keys {
		kid, _ := key["kid"].(string)
		kids = append(kids, kid)
	}
	slices.Sort(kids)
	return kids
}

// REQ-JWK-2: `pulsar keys rotate`, run beside a serving replica, stores a
// new key under a kid of its own, reports it, and exits; pulsar, started
// again, publishes it beside the old key. That a serving replica publishes
// it at its next reload, and when it signs, are internal/signing's to
// test, under testing/synctest.
func TestRunKeysRotate(t *testing.T) {
	t.Parallel()

	env := map[string]string{
		"PULSAR_ISSUER":       loopbackIssuer,
		"PULSAR_DATABASE_URL": postgrestest.NewDatabase(t),
	}
	p := start(t, env)
	addr := p.waitListening()
	p.waitKeysLoaded()
	before := kids(fetchJWKS(t, "http://"+addr+"/jwks"))

	lines, err := runCommand(t, env, "keys", "rotate")
	if err != nil {
		t.Fatalf("run(keys rotate) = %v, want nil", err)
	}
	i := slices.IndexFunc(lines, func(l logLine) bool { return l.Msg == "signing key stored" })
	if i < 0 {
		t.Fatalf("run(keys rotate) logged %+v, want a line %q", lines, "signing key stored")
	}
	added := lines[i].KID
	if added == "" || slices.Contains(before, added) {
		t.Fatalf("run(keys rotate) logged kid %q, want one not in %q", added, before)
	}
	if slices.ContainsFunc(lines, func(l logLine) bool { return l.Msg == "listening" }) {
		t.Errorf("run(keys rotate) logged %q, want it not to serve", "listening")
	}

	if err := p.stop(); err != nil {
		t.Fatalf("run() = %v, want nil", err)
	}
	p = start(t, env)
	addr = p.waitListening()
	p.waitKeysLoaded()
	want := slices.Sorted(slices.Values(append(slices.Clone(before), added)))
	if diff := cmp.Diff(want, kids(fetchJWKS(t, "http://"+addr+"/jwks"))); diff != "" {
		t.Errorf("GET /jwks after keys rotate kids mismatch (-want +got):\n%s", diff)
	}
	if err := p.stop(); err != nil {
		t.Errorf("run() = %v, want nil", err)
	}
}

// pulsar refuses a command it does not know, and a rotation in a database
// that holds no key to rotate, with an error saying why.
func TestRunRefusesCommand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		databaseURL func(testing.TB) string
		args        []string
		want        string // in the error
	}{
		{
			name:        "no key",
			databaseURL: postgrestest.NewDatabase,
			args:        []string{"keys", "rotate"},
			want:        "start pulsar against it first",
		},
		{
			name:        "unknown command",
			databaseURL: postgrestest.UnreachableURL,
			args:        []string{"keys", "delete"},
			want:        `unknown command "keys delete"`,
		},
		{
			name:        "keys without a command",
			databaseURL: postgrestest.UnreachableURL,
			args:        []string{"keys"},
			want:        `unknown command "keys"`,
		},
		{
			name:        "client-secret with an argument",
			databaseURL: postgrestest.UnreachableURL,
			args:        []string{"client-secret", "rp"},
			want:        `unknown command "client-secret rp"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := runCommand(t, map[string]string{
				"PULSAR_ISSUER":       loopbackIssuer,
				"PULSAR_DATABASE_URL": tt.databaseURL(t),
			}, tt.args...)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("run(%s) = %v, want an error containing %q", strings.Join(tt.args, " "), err, tt.want)
			}
		})
	}
}
