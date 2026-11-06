package config

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/palebluedot4/pulsar/internal/oidc"
)

const databaseURL = "postgres://pulsar@localhost:5432/pulsar"

// secret is a valid PULSAR_SECRET, and the bytes it decodes to.
const (
	secret        = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" //nolint:gosec // G101: a test value, guarding nothing.
	secretDecoded = "0123456789abcdef0123456789abcdef"
)

// pgx reads libpq's PG* variables from the process environment, whatever
// getenv is, so an error they cause is reported as possibly theirs rather
// than blamed on PULSAR_DATABASE_URL alone. Not parallel: t.Setenv changes
// the process environment.
func TestLoadNamesPGVariables(t *testing.T) {
	t.Setenv("PGSERVICEFILE", filepath.Join(t.TempDir(), "missing.conf"))
	t.Setenv("PGSERVICE", "pulsar")
	env := map[string]string{
		"PULSAR_ISSUER":       "https://op.example",
		"PULSAR_DATABASE_URL": databaseURL,
		"PULSAR_SECRET":       secret,
	}
	_, err := Load(func(key string) string { return env[key] })
	if err == nil || !strings.Contains(err.Error(), "PULSAR_DATABASE_URL") || !strings.Contains(err.Error(), "PG*") {
		t.Errorf("Load() with PGSERVICE naming a missing service file = %v, want an error naming PULSAR_DATABASE_URL and the PG* variables", err)
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()

	issuer, err := oidc.ParseIssuer("https://op.example")
	if err != nil {
		t.Fatal(err)
	}
	// An Issuer is its string; its URL is not exported.
	byString := cmp.Comparer(func(a, b *oidc.Issuer) bool { return a.String() == b.String() })
	tests := []struct {
		name string
		env  map[string]string
		want Config
	}{
		{
			name: "defaults for optional settings",
			env: map[string]string{
				"PULSAR_ISSUER":       "https://op.example",
				"PULSAR_DATABASE_URL": databaseURL,
				"PULSAR_SECRET":       secret,
			},
			want: Config{Addr: ":8080", Issuer: issuer, DatabaseURL: databaseURL, Secret: Secret([]byte(secretDecoded))},
		},
		{
			name: "every setting from environment",
			env: map[string]string{
				"PULSAR_ADDR":         "127.0.0.1:9000",
				"PULSAR_ISSUER":       "https://op.example",
				"PULSAR_DATABASE_URL": databaseURL,
				"PULSAR_TLS_CERT":     "cert.pem",
				"PULSAR_TLS_KEY":      "key.pem",
				"PULSAR_SECRET":       secret,
			},
			want: Config{
				Addr:        "127.0.0.1:9000",
				Issuer:      issuer,
				DatabaseURL: databaseURL,
				Secret:      Secret([]byte(secretDecoded)),
				TLSCertFile: "cert.pem",
				TLSKeyFile:  "key.pem",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			getenv := func(key string) string { return tt.env[key] }
			got, err := Load(getenv)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got, byString); diff != "" {
				t.Errorf("Load() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// REQ-JWK-4: a Config printed or logged by mistake does not disclose the
// secret, a symmetric key with which anyone who reads the database has the
// private signing keys.
func TestSecretDoesNotFormat(t *testing.T) {
	t.Parallel()

	cfg, err := Load(func(key string) string {
		return map[string]string{
			"PULSAR_ISSUER":       "https://op.example",
			"PULSAR_DATABASE_URL": databaseURL,
			"PULSAR_SECRET":       secret,
		}[key]
	})
	if err != nil {
		t.Fatal(err)
	}
	// The forms in which fmt prints a byte array's contents.
	raw := [SecretSize]byte([]byte(secretDecoded))
	forms := []string{
		secretDecoded,
		hex.EncodeToString(raw[:]),
		strings.Trim(fmt.Sprint(raw), "[]"),
		strings.TrimSuffix(strings.TrimPrefix(fmt.Sprintf("%#v", raw), "[32]uint8{"), "}"),
	}
	printed := make(map[string]string) // how cfg was printed → the result
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%q", "%d"} {
		printed[fmt.Sprintf("fmt.Sprintf(%q, cfg)", verb)] = fmt.Sprintf(verb, cfg)
	}
	b, err := json.Marshal(cfg) //nolint:gosec // G117: the test checks that the secret is not encoded.
	if err != nil {
		t.Fatal(err)
	}
	printed["json.Marshal(cfg)"] = string(b)
	var logged strings.Builder
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("config", "cfg", cfg)
	printed["slog JSON handler"] = logged.String()

	for how, got := range printed {
		for _, form := range forms {
			if strings.Contains(got, form) {
				t.Errorf("%s = %q, want it without the secret", how, got)
				break
			}
		}
	}
}
