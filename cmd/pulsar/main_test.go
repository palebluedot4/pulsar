package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	t.Parallel()

	addr, stop := startRun(t, map[string]string{"PULSAR_ISSUER": "http://127.0.0.1"})
	resp := get(t, http.DefaultClient, "http://"+addr+"/livez")
	if err := resp.Body.Close(); err != nil {
		t.Errorf("close body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /livez status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	if err := stop(); err != nil {
		t.Errorf("run() = %v, want nil after cancellation", err)
	}
}

// REQ-DISC-1, REQ-DISC-17: an issuer that is https, or http on a loopback
// host, is accepted and published exactly as configured.
func TestRunPublishesIssuer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		issuer string
		path   string
	}{
		{issuer: "https://op.example", path: "/.well-known/openid-configuration"},
		{issuer: "https://op.example:8443/tenant", path: "/tenant/.well-known/openid-configuration"},
		{issuer: "http://127.0.0.1:8080", path: "/.well-known/openid-configuration"},
		{issuer: "http://[::1]", path: "/.well-known/openid-configuration"},
		{issuer: "http://localhost", path: "/.well-known/openid-configuration"},
	}
	for _, tt := range tests {
		t.Run(tt.issuer, func(t *testing.T) {
			t.Parallel()
			addr, stop := startRun(t, map[string]string{"PULSAR_ISSUER": tt.issuer})
			if got := discoveredIssuer(t, http.DefaultClient, "http://"+addr+tt.path); got != tt.issuer {
				t.Errorf("GET %s issuer = %q, want %q", tt.path, got, tt.issuer)
			}
			if err := stop(); err != nil {
				t.Errorf("run() = %v, want nil after cancellation", err)
			}
		})
	}
}

func TestRunServesTLS(t *testing.T) {
	t.Parallel()

	certFile, keyFile, roots := writeCertificate(t)
	addr, stop := startRun(t, map[string]string{
		"PULSAR_ISSUER":   "https://127.0.0.1",
		"PULSAR_TLS_CERT": certFile,
		"PULSAR_TLS_KEY":  keyFile,
	})
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}}
	if got, want := discoveredIssuer(t, client, "https://"+addr+"/.well-known/openid-configuration"), "https://127.0.0.1"; got != want {
		t.Errorf("GET /.well-known/openid-configuration over TLS issuer = %q, want %q", got, want)
	}
	if err := stop(); err != nil {
		t.Errorf("run() = %v, want nil after cancellation", err)
	}
}

// REQ-DISC-1: the issuer must be an https URL with no query or fragment; the
// loopback exception is the departure recorded beside it. REQ-DISC-13: an
// issuer never has a terminating slash to remove.
func TestRunRefusesInvalidConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		env     map[string]string
		setting string // the setting the error must name
	}{
		{name: "missing issuer", env: map[string]string{}, setting: "PULSAR_ISSUER"},
		{name: "relative issuer", env: map[string]string{"PULSAR_ISSUER": "/op"}, setting: "PULSAR_ISSUER"},
		{name: "issuer without host", env: map[string]string{"PULSAR_ISSUER": "https:///op"}, setting: "PULSAR_ISSUER"},
		{name: "http issuer", env: map[string]string{"PULSAR_ISSUER": "http://op.example"}, setting: "PULSAR_ISSUER"},
		{name: "http issuer under localhost", env: map[string]string{"PULSAR_ISSUER": "http://localhost.op.example"}, setting: "PULSAR_ISSUER"},
		{name: "other scheme", env: map[string]string{"PULSAR_ISSUER": "ftp://op.example"}, setting: "PULSAR_ISSUER"},
		{name: "issuer with fragment", env: map[string]string{"PULSAR_ISSUER": "https://op.example#top"}, setting: "PULSAR_ISSUER"},
		{name: "issuer with empty fragment", env: map[string]string{"PULSAR_ISSUER": "https://op.example#"}, setting: "PULSAR_ISSUER"},
		{name: "issuer with query", env: map[string]string{"PULSAR_ISSUER": "https://op.example?tenant=a"}, setting: "PULSAR_ISSUER"},
		{name: "issuer with empty query", env: map[string]string{"PULSAR_ISSUER": "https://op.example?"}, setting: "PULSAR_ISSUER"},
		{name: "issuer with userinfo", env: map[string]string{"PULSAR_ISSUER": "https://user@op.example"}, setting: "PULSAR_ISSUER"},
		{name: "issuer with empty port", env: map[string]string{"PULSAR_ISSUER": "https://op.example:"}, setting: "PULSAR_ISSUER"},
		{name: "issuer with default https port", env: map[string]string{"PULSAR_ISSUER": "https://op.example:443"}, setting: "PULSAR_ISSUER"},
		{name: "issuer with default http port", env: map[string]string{"PULSAR_ISSUER": "http://localhost:80"}, setting: "PULSAR_ISSUER"},
		{name: "issuer with uppercase host", env: map[string]string{"PULSAR_ISSUER": "https://OP.example"}, setting: "PULSAR_ISSUER"},
		{name: "issuer with dot segment", env: map[string]string{"PULSAR_ISSUER": "https://op.example/."}, setting: "PULSAR_ISSUER"},
		{name: "issuer with encoded dot segment", env: map[string]string{"PULSAR_ISSUER": "https://op.example/%2e"}, setting: "PULSAR_ISSUER"},
		{name: "issuer with dot-dot segment", env: map[string]string{"PULSAR_ISSUER": "https://op.example/a/../b"}, setting: "PULSAR_ISSUER"},
		{name: "issuer with empty segment", env: map[string]string{"PULSAR_ISSUER": "https://op.example//tenant"}, setting: "PULSAR_ISSUER"},
		{name: "issuer not in canonical form", env: map[string]string{"PULSAR_ISSUER": "HTTPS://op.example"}, setting: "PULSAR_ISSUER"},
		{name: "issuer ending with slash", env: map[string]string{"PULSAR_ISSUER": "https://op.example/"}, setting: "PULSAR_ISSUER"},
		{name: "issuer path ending with slash", env: map[string]string{"PULSAR_ISSUER": "https://op.example/tenant/"}, setting: "PULSAR_ISSUER"},
		{
			name: "TLS with http issuer",
			env: map[string]string{
				"PULSAR_ISSUER":   "http://127.0.0.1",
				"PULSAR_TLS_CERT": "cert.pem",
				"PULSAR_TLS_KEY":  "key.pem",
			},
			setting: "PULSAR_ISSUER",
		},
		{
			name:    "certificate without key",
			env:     map[string]string{"PULSAR_ISSUER": "https://op.example", "PULSAR_TLS_CERT": "cert.pem"},
			setting: "PULSAR_TLS_KEY",
		},
		{
			name:    "key without certificate",
			env:     map[string]string{"PULSAR_ISSUER": "https://op.example", "PULSAR_TLS_KEY": "key.pem"},
			setting: "PULSAR_TLS_CERT",
		},
		{
			name: "unreadable certificate and key",
			env: map[string]string{
				"PULSAR_ISSUER":   "https://op.example",
				"PULSAR_TLS_CERT": "testdata/missing-cert.pem",
				"PULSAR_TLS_KEY":  "testdata/missing-key.pem",
			},
			setting: "PULSAR_TLS_CERT",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// The context is canceled from the start, so a configuration
			// wrongly accepted makes run return at once instead of serving.
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			env := maps.Clone(tt.env)
			env["PULSAR_ADDR"] = "127.0.0.1:0"
			getenv := func(key string) string { return env[key] }
			err := run(ctx, nil, getenv, strings.NewReader(""), io.Discard, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tt.setting) {
				t.Errorf("run() = %v, want an error naming %s", err, tt.setting)
			}
		})
	}
}

func TestRunDoesNotEchoIssuerPassword(t *testing.T) {
	t.Parallel()

	const password = "hunter2"
	issuers := []string{
		"https://user:" + password + "@op.example",
		"https://user:" + password + "@op.example:abc", // fails to parse
		"https://user:" + password + "@/tenant",        // has no host
	}
	for _, issuer := range issuers {
		t.Run(issuer, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			cancel() // As in TestRunRefusesInvalidConfig.
			env := map[string]string{"PULSAR_ADDR": "127.0.0.1:0", "PULSAR_ISSUER": issuer}
			getenv := func(key string) string { return env[key] }
			err := run(ctx, nil, getenv, strings.NewReader(""), io.Discard, io.Discard)
			if err == nil || !strings.Contains(err.Error(), "PULSAR_ISSUER") || strings.Contains(err.Error(), password) {
				t.Errorf("run() = %v, want an error naming PULSAR_ISSUER without the password", err)
			}
		})
	}
}

// startRun runs the program on a loopback port with env as its whole
// environment, and returns the address it listens on and a function that
// stops it and returns run's result.
func startRun(t *testing.T, env map[string]string) (addr string, stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	env = maps.Clone(env)
	env["PULSAR_ADDR"] = "127.0.0.1:0"
	getenv := func(key string) string { return env[key] }
	logs, stdout := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, nil, getenv, strings.NewReader(""), stdout, io.Discard)
		_ = stdout.Close() // An io.PipeWriter's Close always returns nil.
	}()

	addr = listenAddr(t, logs)
	go io.Copy(io.Discard, logs) //nolint:errcheck // Draining the pipe; its errors are irrelevant.
	return addr, func() error {
		cancel()
		return <-done
	}
}

// get sends a GET request to url and fails the test if none comes back.
func get(t *testing.T, client *http.Client, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

// discoveredIssuer fetches the discovery document at url and returns its
// issuer.
func discoveredIssuer(t *testing.T, client *http.Client, url string) string {
	t.Helper()
	resp := get(t, client, url)
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("close body: %v", err)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want %d", url, resp.StatusCode, http.StatusOK)
	}
	var doc struct {
		Issuer string `json:"issuer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("GET %s: decode body: %v", url, err)
	}
	return doc.Issuer
}

// writeCertificate writes a self-signed certificate for 127.0.0.1, and its
// key, to PEM files, and returns their names and a pool that trusts it.
func writeCertificate(t *testing.T) (certFile, keyFile string, roots *x509.CertPool) {
	t.Helper()
	// Not cryptotest.SetGlobalRandom: the key need not be reproducible, and
	// resetting the process-wide source at cleanup races with TLS
	// connections that close in the background. Closing the client's
	// connections first is not enough: the server's connection goroutines
	// send their own close_notify after Shutdown returns.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The client checks the validity period against the wall clock, so
	// this cannot run in a synctest bubble.
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		t.Fatal(err)
	}
	roots = x509.NewCertPool()
	roots.AddCert(cert)
	return certFile, keyFile, roots
}

// listenAddr reads JSON log lines until the server reports the address it
// is listening on.
func listenAddr(t *testing.T, logs io.Reader) string {
	t.Helper()
	sc := bufio.NewScanner(logs)
	for sc.Scan() {
		var line struct {
			Msg  string `json:"msg"`
			Addr string `json:"addr"`
		}
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatalf("log line %q is not JSON: %v", sc.Text(), err)
		}
		if line.Msg == "listening" {
			return line.Addr
		}
	}
	t.Fatalf("server exited before listening: %v", sc.Err())
	return ""
}
