package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
)

// accessTokenOf returns the access token of a successful token response,
// failing the test for any other.
func accessTokenOf(t *testing.T, resp response) string {
	t.Helper()
	if resp.status != http.StatusOK {
		t.Fatalf("POST %s status = %d, want %d; body %q", tokenPath, resp.status, http.StatusOK, resp.body)
	}
	var tokens struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(resp.body), &tokens); err != nil {
		t.Fatalf("POST %s body %q is not a token response: %v", tokenPath, resp.body, err)
	}
	return tokens.AccessToken
}

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
				accessToken := accessTokenOf(t, tokenRequest(t, handler, "rp", rpSecret, form))
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

// REQ-OAUTH-29: a redemption that is refused by its Client, sent while
// another redemption of the code is in progress, waits for that one to
// commit and then revokes the access token it recorded. A refused Client
// does not wait on the code's row as a second redemption by the right one
// does, so this is what locking the row first gives. The redemption in
// progress is the test's own transaction, which marks the code redeemed
// and records a token as the token endpoint does, and commits once the
// request waits on a lock.
func TestTokenCodeReuseWaitsForRedemptionInProgress(t *testing.T) {
	t.Parallel()

	pool := postgrestest.Open(t, postgrestest.NewDatabase(t))
	handler := newFlowHandler(t, pool)
	issued, _ := issuedTokens(t, handler, withScope("openid"))
	claims := verify(t, handler, issued).claims
	jti := rand.Text()
	claims["jti"] = jti
	accessToken := forge(t, forger(t, pool), "at+jwt", claims)
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
	if _, err := tx.Exec(ctx, "INSERT INTO access_tokens (jti, code_hash, expiry) VALUES ($1, $2, $3)", jti, hash[:], time.Now().Add(10*time.Minute)); err != nil {
		t.Fatalf("recording the access token: %v", err)
	}

	done := make(chan response, 1)
	go func() { done <- tokenRequest(t, handler, "other", otherSecret, codeForm(c)) }()
	for waiting := false; !waiting; {
		select {
		case resp := <-done:
			t.Fatalf("POST %s finished while a redemption of its code was in progress, want it to wait; body %q", tokenPath, resp.body)
		default:
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

	if got := tokenErrorCode(t, <-done, http.StatusBadRequest); got != "invalid_grant" {
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
	reused := accessTokenOf(t, tokenRequest(t, handler, "rp", rpSecret, form))
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
			accessToken = accessTokenOf(t, r)
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
