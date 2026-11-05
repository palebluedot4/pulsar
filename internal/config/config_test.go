package config

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestLoad(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		env  map[string]string
		want Config
	}{
		{
			name: "defaults",
			env:  nil,
			want: Config{Addr: ":8080"},
		},
		{
			name: "address from environment",
			env:  map[string]string{"PULSAR_ADDR": "127.0.0.1:9000"},
			want: Config{Addr: "127.0.0.1:9000"},
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
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Load() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
