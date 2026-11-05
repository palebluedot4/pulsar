// Package config loads pulsar's configuration from the environment.
package config

// Config is pulsar's runtime configuration.
type Config struct {
	// Addr is the TCP address the HTTP server listens on.
	Addr string
}

// Load reads the configuration through getenv, which has the signature of
// [os.Getenv] so that tests can supply their own environment.
func Load(getenv func(string) string) (Config, error) {
	cfg := Config{Addr: ":8080"}
	if v := getenv("PULSAR_ADDR"); v != "" {
		cfg.Addr = v
	}
	return cfg, nil
}
