package config

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/palebluedot4/pulsar/internal/oidc"
)

const databaseURL = "postgres://pulsar@localhost:5432/pulsar"

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
			},
			want: Config{Addr: ":8080", Issuer: issuer, DatabaseURL: databaseURL},
		},
		{
			name: "every setting from environment",
			env: map[string]string{
				"PULSAR_ADDR":         "127.0.0.1:9000",
				"PULSAR_ISSUER":       "https://op.example",
				"PULSAR_DATABASE_URL": databaseURL,
				"PULSAR_TLS_CERT":     "cert.pem",
				"PULSAR_TLS_KEY":      "key.pem",
			},
			want: Config{
				Addr:        "127.0.0.1:9000",
				Issuer:      issuer,
				DatabaseURL: databaseURL,
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
