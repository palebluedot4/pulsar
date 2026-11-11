package server

// The tests in this file make PostgreSQL fail at one step of a request,
// in the test's own database, by the means postgrestest describes: a
// trigger that raises on a write, or a lock held past lock_timeout for a
// read. Each checks what the Client or the End-User gets when that step
// fails: an error, and never the code, token, page or redirect that the
// step's success would have led to, nor a claim that something was done
// that was not. docs/mutation-testing.md lists the steps whose failure no
// test here makes, and why.

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
)

// The locks a test holds, through postgrestest.Hold, to make a read fail:
// a table lock that stops every statement on the table, a plain SELECT
// included, and row locks that stop a SELECT ... FOR UPDATE or FOR NO KEY
// UPDATE of the rows.
const (
	lockLoginSessions = "LOCK TABLE login_sessions IN ACCESS EXCLUSIVE MODE"
	lockConsents      = "LOCK TABLE consents IN ACCESS EXCLUSIVE MODE"
	lockCodes         = "SELECT FROM authorization_codes FOR UPDATE"
	lockFamilies      = "SELECT FROM refresh_token_families FOR UPDATE"
)

// breakStep makes one step of a request fail in the database at
// databaseURL, from when it is called until the test ends.
type breakStep func(t *testing.T, databaseURL string)

// failOn returns a breakStep that makes every statement of kind op on table
// fail (postgrestest.FailOn).
func failOn(op, table string) breakStep {
	return func(t *testing.T, databaseURL string) {
		t.Helper()
		postgrestest.FailOn(t, databaseURL, op, table)
	}
}

// hold returns a breakStep that holds the lock statement takes, which a
// statement of the handler newFailingFlowHandler returns gives up waiting
// for (postgrestest.Hold).
func hold(statement string) breakStep {
	return func(t *testing.T, databaseURL string) {
		t.Helper()
		postgrestest.Hold(t, databaseURL, statement)
	}
}

// newFailingFlowHandler returns the handler of newFlowHandler for a new
// database, and the database's URL, for a breakStep. Its statements wait
// for a lock no longer than lock_timeout (postgrestest.WithLockTimeout).
func newFailingFlowHandler(t *testing.T) (http.Handler, string) {
	t.Helper()
	databaseURL := postgrestest.NewDatabase(t)
	return newFlowHandler(t, postgrestest.Open(t, postgrestest.WithLockTimeout(t, databaseURL))), databaseURL
}

// REQ-OAUTH-51, REQ-OAUTH-9, REQ-ISS-2: an authorization request whose
// Login Session or Consent cannot be read or stored gets server_error at
// the Client's redirect URI: no code, no consent page, and no empty page.
func TestAuthorizationDatabaseFailure(t *testing.T) {
	t.Parallel()

	// signedInWithConsent signs b in as alice, with her Consent to rp's
	// request.
	signedInWithConsent := func(b *browser) response {
		b.t.Helper()
		wantCode(b.t, b.decide(b.signIn(b.authorize(http.MethodGet, authorizationParams())), "allow"), "request before the failure")
		return response{}
	}
	authorizeAgain := func(b *browser, _ response) response {
		b.t.Helper()
		return b.authorize(http.MethodGet, authorizationParams())
	}
	tests := []struct {
		name string
		// before takes the steps before the one that fails, and returns
		// the response the failing request follows from.
		before    func(b *browser) response
		breakStep breakStep
		// request sends the request whose step fails.
		request func(b *browser, prev response) response
	}{
		{
			name:      "Login Session not read",
			before:    signedInWithConsent,
			breakStep: hold(lockLoginSessions),
			request:   authorizeAgain,
		},
		{
			name:      "Login Session not saved",
			before:    signedInWithConsent,
			breakStep: failOn("INSERT", "login_sessions"),
			request:   authorizeAgain,
		},
		{
			name: "Consent not stored",
			before: func(b *browser) response {
				b.t.Helper()
				return b.signIn(b.authorize(http.MethodGet, authorizationParams()))
			},
			breakStep: failOn("INSERT", "consents"),
			request: func(b *browser, consentPage response) response {
				b.t.Helper()
				return b.decide(consentPage, "allow")
			},
		},
		{
			name: "Consent not read",
			before: func(b *browser) response {
				b.t.Helper()
				return b.authorize(http.MethodGet, authorizationParams())
			},
			breakStep: hold(lockConsents),
			request: func(b *browser, toLogin response) response {
				b.t.Helper()
				return b.signIn(toLogin)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			handler, databaseURL := newFailingFlowHandler(t)
			b := &browser{t: t, handler: handler}
			prev := tt.before(b)
			tt.breakStep(t, databaseURL)
			resp := tt.request(b, prev)
			want := url.Values{"error": {"server_error"}, "state": {"af0ifjsldkj"}, "iss": {loginIssuer}}
			if diff := cmp.Diff(want, errorResponse(t, resp)); diff != "" {
				t.Errorf("authorization request with the %s: error response mismatch (-want +got):\n%s", tt.name, diff)
			}
		})
	}
}

// REQ-OAUTH-15: a token request whose code, refresh token or the tokens
// issued for it cannot be read or recorded gets 500 and server_error, and
// no token. That includes a code presented again, or a refresh token
// presented again, whose tokens cannot be revoked.
func TestTokenDatabaseFailure(t *testing.T) {
	t.Parallel()

	c := rpNoPKCE
	// Each takes the steps before the one that fails, and returns a func
	// that sends the token request whose step fails.
	redeemCode := func(t *testing.T, handler http.Handler) func() response {
		t.Helper()
		form := c.form(c.code(t, handler), "")
		return func() response { return c.redeem(t, handler, form) }
	}
	redeemOfflineCode := func(t *testing.T, handler http.Handler) func() response {
		t.Helper()
		form := c.form(c.offlineCode(t, handler, nil), "")
		return func() response { return c.redeem(t, handler, form) }
	}
	redeemCodeAgain := func(t *testing.T, handler http.Handler) func() response {
		t.Helper()
		form := c.form(c.code(t, handler), "")
		tokenResponseOf(t, c.redeem(t, handler, form))
		return func() response { return c.redeem(t, handler, form) }
	}
	refresh := func(t *testing.T, handler http.Handler) func() response {
		t.Helper()
		first := c.offlineTokens(t, handler, "", nil)
		return func() response { return c.refresh(t, handler, first.RefreshToken, "") }
	}
	refreshAgain := func(t *testing.T, handler http.Handler) func() response {
		t.Helper()
		first := c.offlineTokens(t, handler, "", nil)
		tokenResponseOf(t, c.refresh(t, handler, first.RefreshToken, ""))
		return func() response { return c.refresh(t, handler, first.RefreshToken, "") }
	}
	tests := []struct {
		name      string
		setUp     func(t *testing.T, handler http.Handler) (send func() response)
		breakStep breakStep
	}{
		{name: "code not redeemed", setUp: redeemCode, breakStep: failOn("UPDATE", "authorization_codes")},
		{name: "access token not recorded", setUp: redeemCode, breakStep: failOn("INSERT", "access_tokens")},
		{name: "Refresh Token Family not started", setUp: redeemOfflineCode, breakStep: failOn("INSERT", "refresh_token_families")},
		{name: "refresh token not recorded", setUp: redeemOfflineCode, breakStep: failOn("INSERT", "refresh_tokens")},
		{name: "code presented again not locked", setUp: redeemCodeAgain, breakStep: hold(lockCodes)},
		{name: "tokens of a code presented again not revoked", setUp: redeemCodeAgain, breakStep: failOn("DELETE", "access_tokens")},
		{name: "Refresh Token Family not locked", setUp: refresh, breakStep: hold(lockFamilies)},
		{name: "refresh token not marked used", setUp: refresh, breakStep: failOn("UPDATE", "refresh_tokens")},
		{name: "replacement refresh token not recorded", setUp: refresh, breakStep: failOn("INSERT", "refresh_tokens")},
		{name: "access token of a refresh not recorded", setUp: refresh, breakStep: failOn("INSERT", "access_tokens")},
		{name: "family of a refresh token presented again not revoked", setUp: refreshAgain, breakStep: failOn("UPDATE", "refresh_token_families")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			handler, databaseURL := newFailingFlowHandler(t)
			send := tt.setUp(t, handler)
			tt.breakStep(t, databaseURL)
			if got := tokenErrorCode(t, send(), http.StatusInternalServerError); got != "server_error" {
				t.Errorf("POST %s with the %s: error = %q, want %q", tokenPath, tt.name, got, "server_error")
			}
		})
	}
}

// REQ-REVOKE-10, REQ-REVOKE-12: a revocation request whose token cannot
// be revoked, because its record or its Refresh Token Family cannot be
// read or changed, gets 500 and server_error, never the 200 that tells the
// Client the token is revoked.
func TestRevocationDatabaseFailure(t *testing.T) {
	t.Parallel()

	c := rpNoPKCE
	refreshToken := func(r tokenResponse) string { return r.RefreshToken }
	tests := []struct {
		name      string
		token     func(tokenResponse) string // the token revoked
		breakStep breakStep
	}{
		{name: "Refresh Token Family not locked", token: refreshToken, breakStep: hold(lockFamilies)},
		{name: "Refresh Token Family not revoked", token: refreshToken, breakStep: failOn("UPDATE", "refresh_token_families")},
		{name: "access tokens of a Refresh Token Family not revoked", token: refreshToken, breakStep: failOn("DELETE", "access_tokens")},
		{name: "access token not revoked", token: func(r tokenResponse) string { return r.AccessToken }, breakStep: failOn("DELETE", "access_tokens")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			handler, databaseURL := newFailingFlowHandler(t)
			tokens := c.offlineTokens(t, handler, "", nil)
			tt.breakStep(t, databaseURL)
			if got := revocationErrorCode(t, c.revoke(t, handler, tt.token(tokens), ""), http.StatusInternalServerError); got != "server_error" {
				t.Errorf("POST %s with the %s: error = %q, want %q", revocationPath, tt.name, got, "server_error")
			}
		})
	}
}

// A logout request, or the End-User's answer to it, whose Login Session
// cannot be read or stored gets 500: no confirmation page, and no
// redirect to the Client or page that says the End-User is signed out, or
// still signed in, when that is not what was stored. It cites no
// requirement: RP-Initiated Logout 1.0 does not say how an OP answers a
// failure of its own. TestLogoutNotEnded is the case of a Login Session
// that cannot be ended.
func TestLogoutDatabaseFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// answer is the End-User's answer to the confirmation page, or ""
		// if the request that fails is the logout request itself.
		answer    string
		breakStep breakStep
	}{
		{name: "Login Session not read", breakStep: hold(lockLoginSessions)},
		{name: "Login Session not saved", breakStep: failOn("INSERT", "login_sessions")},
		{name: "Login Session not read for the confirmation", answer: confirmLogout, breakStep: hold(lockLoginSessions)},
		{name: "Login Session not saved for staying signed in", answer: declineLogout, breakStep: failOn("INSERT", "login_sessions")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			handler, databaseURL := newFailingFlowHandler(t)
			b, hint := signedInWithHint(t, handler)
			resp := failedLogout(b, hint, tt.answer, func() { tt.breakStep(t, databaseURL) })
			if resp.status != http.StatusInternalServerError {
				t.Errorf("logout with the %s: status = %d, want %d; Location %q", tt.name, resp.status, http.StatusInternalServerError, resp.header.Get("Location"))
			}
		})
	}
}

// failedLogout sends the browser b, signed in, to the logout endpoint with
// hint and rp's post-logout redirect URI, and answers the confirmation
// page with answer unless it is "". It calls breakStep before the last of
// those requests, and returns that request's response.
func failedLogout(b *browser, hint, answer string, breakStep func()) response {
	b.t.Helper()
	params := url.Values{"id_token_hint": {hint}, "post_logout_redirect_uri": {rpSignedOutURI}}
	if answer == "" {
		breakStep()
		return b.logout(http.MethodGet, params)
	}
	page := b.logout(http.MethodGet, params)
	breakStep()
	return b.answerLogout(page, answer)
}

// REQ-LOGOUT-8: an End-User who says yes is logged out, so one whose Login
// Session cannot be ended is not told so: the answer gets 500, and they
// are still signed in.
func TestLogoutNotEnded(t *testing.T) {
	t.Parallel()

	handler, databaseURL := newFailingFlowHandler(t)
	b, hint := signedInWithHint(t, handler)
	resp := failedLogout(b, hint, confirmLogout, func() { postgrestest.FailOn(t, databaseURL, "DELETE", "login_sessions") })
	if resp.status != http.StatusInternalServerError {
		t.Errorf("confirmed logout whose Login Session is not ended: status = %d, want %d; Location %q", resp.status, http.StatusInternalServerError, resp.header.Get("Location"))
	}
	wantSignedIn(t, b, "after a logout whose Login Session was not ended")
}
