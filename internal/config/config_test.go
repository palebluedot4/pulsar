package config

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/palebluedot4/pulsar/internal/oidc"
)

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
			env:  map[string]string{"PULSAR_ISSUER": "https://op.example"},
			want: Config{Addr: ":8080", Issuer: issuer},
		},
		{
			name: "every setting from environment",
			env: map[string]string{
				"PULSAR_ADDR":     "127.0.0.1:9000",
				"PULSAR_ISSUER":   "https://op.example",
				"PULSAR_TLS_CERT": "cert.pem",
				"PULSAR_TLS_KEY":  "key.pem",
			},
			want: Config{Addr: "127.0.0.1:9000", Issuer: issuer, TLSCertFile: "cert.pem", TLSKeyFile: "key.pem"},
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
