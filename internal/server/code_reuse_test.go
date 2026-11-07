package server

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palebluedot4/pulsar/internal/oidc"
	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
)

// REQ-OAUTH-29, REQ-OAUTH-19, REQ-AT-11: a second redemption of a code by
// its own Client, with its redirect URI and, if it was issued with a code
// challenge, the matching code_verifier, fails with invalid_grant, and
// UserInfo then refuses the access token issued from the code with 401 and
// invalid_token: at once, 30 seconds later, and after the code has
// expired, while the token has not, even once the records due have been
// deleted.
func TestTokenCodeReuseRevokesTokens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		wait     time.Duration // between the two redemptions
		client   pkceClient
		verifier string // the code_verifier of both redemptions, if any
		// deleteDue is whether the records due are deleted after the wait.
		deleteDue bool
	}{
		{name: "at once", client: rpNoPKCE},
		{name: "30 seconds later", wait: 30 * time.Second, client: rpNoPKCE},
		{name: "after the code expired", wait: 5 * time.Minute, client: rpNoPKCE},
		{name: "after the code expired and the records due were deleted", wait: 5 * time.Minute, client: rpNoPKCE, deleteDue: true},
		{name: "with PKCE", client: rpPKCE, verifier: pkceVerifier},
		{name: "by a public Client", client: publicPKCE, verifier: pkceVerifier},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
			synctest.Test(t, func(t *testing.T) {
				pool := newBubblePool(t, databaseURL)
				handler := newFlowHandler(t, pool)
				form := tt.client.form(tt.client.code(t, handler), tt.verifier)
				accessToken, _ := tokensOf(t, tt.client.redeem(t, handler, form))
				time.Sleep(tt.wait)
				if tt.deleteDue {
					deleteDue(t, pool)
				}
				if diff := cmp.Diff(claimsOf(aliceProfile), userInfoClaims(t, userInfo(t, handler, getHeader, accessToken))); diff != "" {
					t.Errorf("UserInfo before the second redemption claims mismatch (-want +got):\n%s", diff)
				}

				if got := tokenErrorCode(t, tt.client.redeem(t, handler, form), http.StatusBadRequest); got != "invalid_grant" {
					t.Errorf("second POST %s error = %q, want %q", tokenPath, got, "invalid_grant")
				}
				if got := userInfoError(t, userInfo(t, handler, getHeader, accessToken), http.StatusUnauthorized); got != "invalid_token" {
					t.Errorf("UserInfo after the second redemption error = %q, want %q", got, "invalid_token")
				}
			})
		})
	}
}

// REQ-OAUTH-29, REQ-BCP-11: a second redemption of a code issued with
// offline access, by its own Client, with its redirect URI and matching
// code_verifier, revokes the Refresh Token Family the code started: it
// fails with invalid_grant, the family's newest refresh token then fails
// with invalid_grant too, and UserInfo refuses with 401 the access tokens
// issued in the family not yet expired: the one from a refresh, and the
// one from the code unless it has expired in the wait. It does so at
// once, after the code has expired, and a day later, each time after the
// records due have been deleted: a code is kept while its family lives.
func TestTokenCodeReuseRevokesFamily(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		wait     time.Duration // between the code's redemption and the refresh before the second
		client   pkceClient
		verifier string
	}{
		{name: "at once", client: rpNoPKCE},
		{name: "after the code expired", wait: 2 * time.Minute, client: rpNoPKCE},
		{name: "a day later", wait: 24 * time.Hour, client: rpNoPKCE},
		{name: "a day later, by a public Client", wait: 24 * time.Hour, client: publicPKCE, verifier: pkceVerifier},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
			synctest.Test(t, func(t *testing.T) {
				pool := newBubblePool(t, databaseURL)
				handler := newFlowHandler(t, pool)
				form := tt.client.form(tt.client.offlineCode(t, handler, nil), tt.verifier)
				first := tokenResponseOf(t, tt.client.redeem(t, handler, form))
				time.Sleep(tt.wait)
				refreshed := tokenResponseOf(t, tt.client.refresh(t, handler, first.RefreshToken, ""))
				deleteDue(t, pool)
				// The access tokens of the family not yet expired: the
				// refresh's, and the code's unless the wait outlasted it.
				accessTokens := []string{refreshed.AccessToken}
				if tt.wait < oidc.TokenLifetime {
					accessTokens = append(accessTokens, first.AccessToken)
				}
				wantAccepted(t, handler, "before the second redemption", claimsOf(), accessTokens)

				if got := tokenErrorCode(t, tt.client.redeem(t, handler, form), http.StatusBadRequest); got != "invalid_grant" {
					t.Errorf("second POST %s error = %q, want %q", tokenPath, got, "invalid_grant")
				}
				tt.client.wantRevoked(t, handler, refreshed.RefreshToken, accessTokens)
			})
		})
	}
}

// REQ-OAUTH-29, REQ-OAUTH-8, REQ-OAUTH-14, REQ-OAUTH-19, REQ-OAUTH-26,
// REQ-PKCE-4: a second redemption of a code whose parameters are not those
// of a valid request revokes nothing (OAuth 2.1 draft -17 §7.5.3): one by
// another Client, for another redirect URI, or with a code_verifier that
// does not match fails with invalid_grant; one whose Client fails to
// authenticate, or authenticates by a method other than the one it
// registered, fails with invalid_client. Either way, UserInfo still
// accepts the access token issued from the code, and, for a code issued
// with offline access, the refresh token issued from it is still redeemed.
func TestTokenCodeReuseWithInvalidParametersRevokesNothing(t *testing.T) {
	t.Parallel()

	handler := newFlowHandler(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
	tests := []struct {
		name   string
		client pkceClient // the Client the code is issued to, which redeems it first
		// verifier is the code_verifier of the first redemption, if any.
		verifier string
		// The second redemption: the credentials it sends by HTTP Basic
		// authentication, if any, and its form for the code.
		basic      credentials
		form       func(code string) url.Values
		wantStatus int
		wantError  string
	}{
		{
			name:       "by another Client",
			client:     rpNoPKCE,
			basic:      credentials{"other", otherSecret},
			form:       codeForm,
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_grant",
		},
		{
			name:   "with another redirect URI",
			client: rpNoPKCE,
			basic:  credentials{"rp", rpSecret},
			form: func(code string) url.Values {
				form := codeForm(code)
				form.Set("redirect_uri", rpQueryRedirectURI)
				return form
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_grant",
		},
		{
			name:       "with a code_verifier that does not match",
			client:     rpPKCE,
			verifier:   pkceVerifier,
			basic:      credentials{"rp", rpSecret},
			form:       func(code string) url.Values { return rpPKCE.form(code, wrongVerifier) },
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_grant",
		},
		{
			name:       "without the code_verifier",
			client:     rpPKCE,
			verifier:   pkceVerifier,
			basic:      credentials{"rp", rpSecret},
			form:       codeForm,
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_grant",
		},
		{
			name:       "with a code_verifier for a code without a challenge",
			client:     rpNoPKCE,
			basic:      credentials{"rp", rpSecret},
			form:       func(code string) url.Values { return rpNoPKCE.form(code, pkceVerifier) },
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_grant",
		},
		{
			name:       "by a public Client with a code_verifier that does not match",
			client:     publicPKCE,
			verifier:   pkceVerifier,
			form:       func(code string) url.Values { return publicPKCE.form(code, wrongVerifier) },
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_grant",
		},
		{
			name:       "with a wrong secret",
			client:     rpNoPKCE,
			basic:      credentials{"rp", otherSecret},
			form:       codeForm,
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_client",
		},
		{
			name:   "by a method other than the registered one",
			client: rpNoPKCE,
			form: func(code string) url.Values {
				form := codeForm(code)
				form.Set("client_id", "rp")
				form.Set("client_secret", rpSecret)
				return form
			},
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_client",
		},
	}
	for _, tt := range tests {
		for _, offline := range []bool{false, true} {
			name := tt.name
			if offline {
				name += ", with offline access"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				var c string
				if offline {
					c = tt.client.offlineCode(t, handler, url.Values{"scope": {"openid profile offline_access"}})
				} else {
					c = tt.client.code(t, handler)
				}
				first := tokenResponseOf(t, tt.client.redeem(t, handler, tt.client.form(c, tt.verifier)))

				replay := tokenRequest(t, handler, tt.basic.id, tt.basic.secret, tt.form(c))
				if got := tokenErrorCode(t, replay, tt.wantStatus); got != tt.wantError {
					t.Errorf("second POST %s error = %q, want %q", tokenPath, got, tt.wantError)
				}
				wantAccepted(t, handler, "after the second redemption", claimsOf(aliceProfile), []string{first.AccessToken})
				if offline {
					tokenResponseOf(t, tt.client.refresh(t, handler, first.RefreshToken, ""))
				}
			})
		}
	}
}

// REQ-OAUTH-29: a code whose record has been deleted revokes nothing when
// presented again: without the record, nothing shows that the request's
// parameters are the code's. pulsar deletes a redeemed code's record only
// once its tokens can no longer be revoked; the test deletes it sooner, so
// that the tokens are still there to be revoked.
func TestTokenCodeReuseAfterRecordDeletedRevokesNothing(t *testing.T) {
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
	if diff := cmp.Diff(claimsOf(), userInfoClaims(t, userInfo(t, handler, getHeader, accessToken))); diff != "" {
		t.Errorf("UserInfo after the second redemption claims mismatch (-want +got):\n%s", diff)
	}
}

// REQ-OAUTH-29: a valid second redemption of a code that has expired, sent
// while another redemption of it is in progress, waits for that one to
// commit and then revokes the access token it recorded. A redemption of an
// expired code does not wait on the code's row as one of a code not yet
// expired does, so this is what locking the row first gives.
//
// The redemption in progress is the test's own transaction. It marks the
// code redeemed and moves to it the record of an access token that
// UserInfo has accepted, issued from another code, and commits once the
// request waits on a lock.
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
	if _, err := pool.Exec(ctx, "UPDATE authorization_codes SET expiry = $1 WHERE code_hash = $2", time.Now().Add(-time.Minute), hash[:]); err != nil {
		t.Fatalf("expiring the code: %v", err)
	}
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

	resp := serveWhileLocked(t, pool, handler, newTokenRequest(t, "rp", rpSecret, codeForm(c)), tx)
	if got := tokenErrorCode(t, resp, http.StatusBadRequest); got != "invalid_grant" {
		t.Errorf("POST %s of the expired code error = %q, want %q", tokenPath, got, "invalid_grant")
	}
	if got := userInfoError(t, userInfo(t, handler, getHeader, accessToken), http.StatusUnauthorized); got != "invalid_token" {
		t.Errorf("UserInfo with the token of the redemption in progress error = %q, want %q", got, "invalid_token")
	}
}

// serveWhileLocked serves req on its own goroutine while tx, the test's
// transaction in progress, holds locks the request must wait for. Once a
// backend of the test's database waits on a lock, it commits tx, and
// returns the response. It fails the test if the request finishes first,
// or does not wait within 10 seconds. The wait is on the real clock, not
// in a testing/synctest bubble, since what the request waits on is
// PostgreSQL, which a bubble cannot tell from a goroutine still running.
func serveWhileLocked(t *testing.T, pool *pgxpool.Pool, handler http.Handler, req *http.Request, tx pgx.Tx) response {
	t.Helper()
	// The request is served on its own goroutine, which must not fail the
	// test, so it is sent without the helpers that do.
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		done <- rec
	}()
	ctx := t.Context()
	deadline := time.Now().Add(10 * time.Second)
	for waiting := false; !waiting; {
		select {
		case rec := <-done:
			t.Fatalf("%s %s finished while the test's transaction was in progress, want it to wait; body %q", req.Method, req.URL.Path, rec.Body)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s %s did not wait on a lock within 10s", req.Method, req.URL.Path)
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
	return response{status: rec.Code, header: rec.Header(), body: rec.Body.String()}
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
