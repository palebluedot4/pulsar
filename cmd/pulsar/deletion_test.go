package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
)

// startDeleting runs deleteDue against pool, logging to logger, until the
// test ends, and waits for it to return then.
func startDeleting(t *testing.T, pool *pgxpool.Pool, logger *slog.Logger) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		deleteDue(ctx, pool, logger)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

// insertRecords inserts, under label, a record due at at in each table
// whose records pulsar deletes once due: an authorization code, an access
// token, a Refresh Token Family with a refresh token, a client assertion
// and a Login Session.
func insertRecords(t *testing.T, pool *pgxpool.Pool, label string, at time.Time) {
	t.Helper()
	statements := []string{
		`INSERT INTO authorization_codes (code_hash, client_id, redirect_uri, subject, scopes, nonce, auth_time, expiry, delete_after)
		VALUES (convert_to($1, 'UTF8'), 'rp', 'https://rp.example/callback', 'alice', '{openid}', '', $2, $2, $2)`,
		`INSERT INTO access_tokens (jti, code_hash, expiry) VALUES ($1, convert_to($1, 'UTF8'), $2)`,
		`WITH f AS (
			INSERT INTO refresh_token_families (code_hash, client_id, subject, scopes, claims, auth_time, expiry)
			VALUES (convert_to($1, 'UTF8'), 'rp', 'alice', '{openid,offline_access}', '{}', $2, $2)
			RETURNING id
		)
		INSERT INTO refresh_tokens (token_hash, family_id) SELECT convert_to($1, 'UTF8'), id FROM f`,
		`INSERT INTO client_assertions (client_id, jti_hash, expiry) VALUES ('rp', convert_to($1, 'UTF8'), $2)`,
		`INSERT INTO login_sessions (token, data, expiry) VALUES ($1, '', $2)`,
	}
	for _, s := range statements {
		if _, err := pool.Exec(t.Context(), s, label, at); err != nil {
			t.Fatalf("inserting the records %q: %v", label, err)
		}
	}
}

// records returns the labels of the records insertRecords inserted that
// remain, each prefixed by its table.
func records(t *testing.T, pool *pgxpool.Pool) []string {
	t.Helper()
	rows, err := pool.Query(t.Context(), `
		SELECT 'authorization_codes ' || convert_from(code_hash, 'UTF8') FROM authorization_codes
		UNION ALL SELECT 'access_tokens ' || jti FROM access_tokens
		UNION ALL SELECT 'refresh_token_families ' || convert_from(code_hash, 'UTF8') FROM refresh_token_families
		UNION ALL SELECT 'refresh_tokens ' || convert_from(token_hash, 'UTF8') FROM refresh_tokens
		UNION ALL SELECT 'client_assertions ' || convert_from(jti_hash, 'UTF8') FROM client_assertions
		UNION ALL SELECT 'login_sessions ' || token FROM login_sessions
		ORDER BY 1`)
	if err != nil {
		t.Fatalf("listing the records: %v", err)
	}
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("listing the records: %v", err)
	}
	return got
}

// labeled returns, for each label, the entries records returns for the
// records insertRecords inserted under it.
func labeled(labels ...string) []string {
	want := []string{}
	for _, table := range []string{"access_tokens", "authorization_codes", "client_assertions", "login_sessions", "refresh_token_families", "refresh_tokens"} {
		for _, label := range labels {
			want = append(want, table+" "+label)
		}
	}
	return want
}

// The records due are deleted every deletionInterval, 15 minutes, and not
// before: the authorization codes due, the access tokens, client
// assertions and Login Sessions expired, and the Refresh Token Families
// ended, with their refresh tokens. Those not yet due are kept.
func TestDeleteDueEveryInterval(t *testing.T) {
	t.Parallel()

	if got, want := deletionInterval, 15*time.Minute; got != want {
		t.Errorf("deletionInterval = %v, want %v, Keycloak's default", got, want)
	}
	databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
	synctest.Test(t, func(t *testing.T) {
		pool, err := pgxpool.New(t.Context(), databaseURL)
		if err != nil {
			t.Fatalf("pgxpool.New() error = %v", err)
		}
		t.Cleanup(pool.Close)
		now := time.Now()
		insertRecords(t, pool, "due", now)
		insertRecords(t, pool, "due at the second run", now.Add(2*deletionInterval))
		startDeleting(t, pool, slog.New(slog.NewTextHandler(t.Output(), nil)))

		time.Sleep(deletionInterval - time.Nanosecond)
		synctest.Wait()
		if diff := cmp.Diff(labeled("due", "due at the second run"), records(t, pool)); diff != "" {
			t.Errorf("records just before the first run mismatch (-want +got):\n%s", diff)
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if diff := cmp.Diff(labeled("due at the second run"), records(t, pool)); diff != "" {
			t.Errorf("records after the first run mismatch (-want +got):\n%s", diff)
		}
		time.Sleep(deletionInterval)
		synctest.Wait()
		if diff := cmp.Diff(labeled(), records(t, pool)); diff != "" {
			t.Errorf("records after the second run mismatch (-want +got):\n%s", diff)
		}
	})
}

// syncBuffer is a bytes.Buffer safe for concurrent use.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// messages returns the message of each JSON log line written to b.
func (b *syncBuffer) messages(t *testing.T) []string {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	var msgs []string
	dec := json.NewDecoder(bytes.NewReader(b.buf.Bytes()))
	for dec.More() {
		var line logLine
		if err := dec.Decode(&line); err != nil {
			t.Fatalf("log line is not JSON: %v", err)
		}
		msgs = append(msgs, line.Msg)
	}
	return msgs
}

// A deletion that fails is logged, and the task goes on: the next run
// tries, and logs, again. The pool is closed, so every deletion fails.
func TestDeleteDueLogsFailure(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		pool, err := pgxpool.New(t.Context(), "postgres://127.0.0.1/pulsar")
		if err != nil {
			t.Fatalf("pgxpool.New() error = %v", err)
		}
		pool.Close()
		var logs syncBuffer
		startDeleting(t, pool, slog.New(slog.NewJSONHandler(&logs, nil)))

		failures := []string{"delete due codes and tokens", "delete ended login sessions"}
		time.Sleep(deletionInterval)
		synctest.Wait()
		if diff := cmp.Diff(failures, logs.messages(t)); diff != "" {
			t.Errorf("log after the first run mismatch (-want +got):\n%s", diff)
		}
		time.Sleep(deletionInterval)
		synctest.Wait()
		if diff := cmp.Diff(append(failures, failures...), logs.messages(t)); diff != "" {
			t.Errorf("log after the second run mismatch (-want +got):\n%s", diff)
		}
	})
}
