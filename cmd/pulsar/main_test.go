package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	getenv := func(key string) string {
		if key == "PULSAR_ADDR" {
			return "127.0.0.1:0"
		}
		return ""
	}
	logs, stdout := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, nil, getenv, strings.NewReader(""), stdout, io.Discard)
		_ = stdout.Close() // An io.PipeWriter's Close always returns nil.
	}()

	addr := listenAddr(t, logs)
	go io.Copy(io.Discard, logs) //nolint:errcheck // Draining the pipe; its errors are irrelevant.

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/livez", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /livez: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Errorf("close body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /livez status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	cancel()
	if err := <-done; err != nil {
		t.Errorf("run() = %v, want nil after cancellation", err)
	}
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
