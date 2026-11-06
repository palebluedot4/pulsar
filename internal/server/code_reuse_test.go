package server

import (
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
// later, by another Client, and after the code has expired and its record
// been deleted, while the token has not expired.
func TestTokenCodeReuseRevokesTokens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		wait     time.Duration // between the two redemptions
		clientID string        // of the second redemption
		secret   string
	}{
		{name: "at once", clientID: "rp", secret: rpSecret},
		{name: "30 seconds later", wait: 30 * time.Second, clientID: "rp", secret: rpSecret},
		{name: "by another Client", clientID: "other", secret: otherSecret},
		// A code issued after the first has expired deletes its record.
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
				code(t, handler, withScope("openid"))
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
