package server

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
)

// REQ-OAUTH-29, REQ-OAUTH-19, REQ-AT-11: a second redemption of a code
// fails with invalid_grant, and UserInfo then refuses the access token
// issued from the code with 401 and invalid_token: at once, 30 seconds
// later, by another Client, and after the code has expired, while the
// token has not.
func TestTokenCodeReuseRevokesTokens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		wait time.Duration // between the two redemptions
		// The Client of the second redemption, and its secret.
		clientID, secret string
	}{
		{name: "at once", clientID: "rp", secret: rpSecret},
		{name: "30 seconds later", wait: 30 * time.Second, clientID: "rp", secret: rpSecret},
		{name: "by another Client", clientID: "other", secret: otherSecret},
		{name: "after the code expired", wait: 5 * time.Minute, clientID: "rp", secret: rpSecret},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
			synctest.Test(t, func(t *testing.T) {
				handler := newBubbleFlowHandler(t, databaseURL)
				form := codeForm(code(t, handler, withScope("openid")))
				accessToken, _ := tokensOf(t, tokenRequest(t, handler, "rp", rpSecret, form))
				time.Sleep(tt.wait)
				if diff := cmp.Diff(claimsOf(), userInfoClaims(t, userInfo(t, handler, getHeader, accessToken))); diff != "" {
					t.Errorf("UserInfo before the second redemption claims mismatch (-want +got):\n%s", diff)
				}

				if got := tokenErrorCode(t, tokenRequest(t, handler, tt.clientID, tt.secret, form), http.StatusBadRequest); got != "invalid_grant" {
					t.Errorf("second POST %s error = %q, want %q", tokenPath, got, "invalid_grant")
				}
				if got := userInfoError(t, userInfo(t, handler, getHeader, accessToken), http.StatusUnauthorized); got != "invalid_token" {
					t.Errorf("UserInfo after the second redemption error = %q, want %q", got, "invalid_token")
				}
			})
		})
	}
}

// REQ-OAUTH-29: a code whose record has been deleted, as an expired code's
// is, still revokes the access tokens issued from it.
func TestTokenCodeReuseAfterRecordDeleted(t *testing.T) {
	t.Parallel()

	pool := postgrestest.Open(t, postgrestest.NewDatabase(t))
	handler := newFlowHandler(t, pool)
	c := code(t, handler, withScope("openid"))
	form := codeForm(c)
	accessToken, _ := tokensOf(t, tokenRequest(t, handler, "rp", rpSecret, form))
	hash := sha256.Sum256([]byte(c))
	tag, err := pool.Exec(t.Context(), "DELETE FROM authorization_codes WHERE code_hash = $1", hash[:])
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("deleting the code's record: %d rows, error %v; want 1 row", tag.RowsAffected(), err)
	}

	if got := tokenErrorCode(t, tokenRequest(t, handler, "rp", rpSecret, form), http.StatusBadRequest); got != "invalid_grant" {
		t.Errorf("second POST %s error = %q, want %q", tokenPath, got, "invalid_grant")
	}
	if got := userInfoError(t, userInfo(t, handler, getHeader, accessToken), http.StatusUnauthorized); got != "invalid_token" {
		t.Errorf("UserInfo after the second redemption error = %q, want %q", got, "invalid_token")
	}
}

// REQ-OAUTH-29: a redemption that is refused by its Client, sent while
// another redemption of the code is in progress, waits for that one to
// commit and then revokes the access token it recorded. A refused Client
// does not wait on the code's row as a second redemption by the right one
// does, so this is what locking the row first gives.
//
// The redemption in progress is the test's own transaction. It marks the
// code redeemed and moves to it the record of an access token that
// UserInfo has accepted, issued from another code, and commits once the
// request waits on a lock. The wait for that is on the real clock, not in
// a testing/synctest bubble, since what the request waits on is
// PostgreSQL, which a bubble cannot tell from a goroutine still running.
func TestTokenCodeReuseWaitsForRedemptionInProgress(t *testing.T) {
	t.Parallel()

	pool := postgrestest.Open(t, postgrestest.NewDatabase(t))
	handler := newFlowHandler(t, pool)
	accessToken, _ := issuedTokens(t, handler, withScope("openid"))
	if diff := cmp.Diff(claimsOf(), userInfoClaims(t, userInfo(t, handler, getHeader, accessToken))); diff != "" {
		t.Fatalf("UserInfo before the redemption in progress claims mismatch (-want +got):\n%s", diff)
	}
	jti := verify(t, handler, accessToken).claims["jti"]
	c := code(t, handler, withScope("openid"))
	hash := sha256.Sum256([]byte(c))

	ctx := t.Context()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	if _, err := tx.Exec(ctx, "UPDATE authorization_codes SET redeemed = true WHERE code_hash = $1", hash[:]); err != nil {
		t.Fatalf("marking the code redeemed: %v", err)
	}
	if _, err := tx.Exec(ctx, "UPDATE access_tokens SET code_hash = $1 WHERE jti = $2", hash[:], jti); err != nil {
		t.Fatalf("moving the access token's record to the code: %v", err)
	}

	// The request is served on its own goroutine, which must not fail the
	// test, so it is sent without the helpers that do.
	req := newTokenRequest(t, "other", otherSecret, codeForm(c))
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		done <- rec
	}()
	deadline := time.Now().Add(10 * time.Second)
	for waiting := false; !waiting; {
		select {
		case rec := <-done:
			t.Fatalf("POST %s finished while a redemption of its code was in progress, want it to wait; body %q", tokenPath, rec.Body)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("POST %s did not wait on a lock within 10s", tokenPath)
		}
		err := pool.QueryRow(ctx, "SELECT EXISTS (SELECT FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock')").Scan(&waiting)
		if err != nil {
			t.Fatalf("looking for a backend waiting on a lock: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	rec := <-done
	resp := response{status: rec.Code, header: rec.Header(), body: rec.Body.String()}
	if got := tokenErrorCode(t, resp, http.StatusBadRequest); got != "invalid_grant" {
		t.Errorf("POST %s by another Client error = %q, want %q", tokenPath, got, "invalid_grant")
	}
	if got := userInfoError(t, userInfo(t, handler, getHeader, accessToken), http.StatusUnauthorized); got != "invalid_token" {
		t.Errorf("UserInfo with the token of the redemption in progress error = %q, want %q", got, "invalid_token")
	}
}

// REQ-OAUTH-29: a code that is not redeemed, presented again, revokes no
// access token issued from another code.
func TestTokenCodeReuseRevokesOnlyItsTokens(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	accessToken, _ := issuedTokens(t, handler, withScope("openid"))
	form := codeForm(code(t, handler, withScope("openid")))
	if got := tokenErrorCode(t, tokenRequest(t, handler, "other", otherSecret, form), http.StatusBadRequest); got != "invalid_grant" {
		t.Errorf("POST %s by another Client error = %q, want %q", tokenPath, got, "invalid_grant")
	}
	reused, _ := tokensOf(t, tokenRequest(t, handler, "rp", rpSecret, form))
	if got := tokenErrorCode(t, tokenRequest(t, handler, "rp", rpSecret, form), http.StatusBadRequest); got != "invalid_grant" {
		t.Errorf("second POST %s error = %q, want %q", tokenPath, got, "invalid_grant")
	}
	if diff := cmp.Diff(claimsOf(), userInfoClaims(t, userInfo(t, handler, getHeader, accessToken))); diff != "" {
		t.Errorf("UserInfo with a token of another code claims mismatch (-want +got):\n%s", diff)
	}
	if got := userInfoError(t, userInfo(t, handler, getHeader, reused), http.StatusUnauthorized); got != "invalid_token" {
		t.Errorf("UserInfo with the reused code's token error = %q, want %q", got, "invalid_token")
	}
}

// REQ-OAUTH-16, REQ-OAUTH-29: of token requests that redeem one code at
// once, at most one succeeds, and the others revoke the access token it
// issued, whichever order they commit in.
func TestTokenConcurrentRedemption(t *testing.T) {
	t.Parallel()

	const requests = 8
	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	form := codeForm(code(t, handler, withScope("openid")))
	resps := make([]response, requests)
	var wg sync.WaitGroup
	for i := range requests {
		wg.Go(func() {
			resps[i] = tokenRequest(t, handler, "rp", rpSecret, form)
		})
	}
	wg.Wait()
	counts := map[int]int{}
	var accessToken string
	for _, r := range resps {
		counts[r.status]++
		if r.status == http.StatusOK {
			accessToken, _ = tokensOf(t, r)
		}
	}
	want := map[int]int{http.StatusOK: 1, http.StatusBadRequest: requests - 1}
	if diff := cmp.Diff(want, counts); diff != "" {
		t.Fatalf("statuses of %d concurrent redemptions of one code mismatch (-want +got):\n%s", requests, diff)
	}
	if got := userInfoError(t, userInfo(t, handler, getHeader, accessToken), http.StatusUnauthorized); got != "invalid_token" {
		t.Errorf("UserInfo with the token of a code redeemed %d times error = %q, want %q", requests, got, "invalid_token")
	}
}
