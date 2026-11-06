package login

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"time"
)

// Keys of the values a Login Session holds about the authorization request
// the End-User is going through.
const (
	loginForKey    = "login_for"    // the key of the request the End-User signed in on the login page for
	decisionForKey = "decision_for" // the key of the request the End-User decided on the consent page
	decisionKey    = "decision"     // what they decided, a Decision
	decidedAtKey   = "decided_at"   // when, in seconds since the epoch
)

// interactionLifetime is how long a login or a decision made on a page
// for a request counts as made for it: time enough to read the consent
// page that may follow a login. Past it, the request asks again, so that
// a page left open cannot later stand in for a new login or a decision.
const interactionLifetime = 10 * time.Minute

// requestKey returns the key under which a Login Session records what the
// End-User did for the authorization request whose parameters, encoded as
// a query, are query: a hash, so that the Login Session holds no copy of
// the request.
func requestKey(query string) string {
	sum := sha256.Sum256([]byte(query))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Decision is what the End-User decided on the consent page for an
// authorization request.
type Decision int

// The decisions an [Interaction] can hold.
const (
	Undecided Decision = iota // the consent page was not submitted for the request
	Allowed
	Denied
)

// decisionValues are the values the consent form submits for the
// decisions an End-User can make there.
var decisionValues = map[Decision]string{Allowed: "allow", Denied: "deny"}

// parseDecision returns the decision whose form value is v.
func parseDecision(v string) (Decision, bool) {
	for d, value := range decisionValues {
		if v == value {
			return d, true
		}
	}
	return Undecided, false
}

// HasCookie reports whether r carries a Login Session cookie, valid or
// not. A browser leaves out the SameSite=Lax cookie from a request another
// site sends it by POST.
func (s *Sessions) HasCookie(r *http.Request) bool {
	_, err := r.Cookie(cookieName)
	return err == nil
}

// Interaction is what a browser's Login Session records about one
// authorization request: who is signed in, and what the End-User did on
// the login and consent pages for that request.
//
// The login and consent pages resume an authorization request by sending
// the browser back to the authorization endpoint with the request's own
// parameters. A request whose parameters ask for a page, as prompt=login,
// max_age=0 and prompt=consent do, would send the browser around in a
// circle if the endpoint could not tell that the page had just been
// answered for it: seconds, the unit of auth_time and max_age, are too
// coarse to tell a login just made from one made a moment before the
// request. So each page, when the End-User submits it, records in the
// Login Session the key of the request it was shown for, a hash of the
// request's parameters; the authorization endpoint counts a login or a
// decision only under the key of the request it is serving, and removes
// it, with [Interaction.Finish], when it answers the Client.
//
// A login or a decision so recorded counts for interactionLifetime at
// most, and a decision only for the End-User the consent page was shown
// for. A login clears the Login Session, so a decision recorded for a
// request was made after the login recorded for it, if any.
//
// The record is server-side, in a Login Session that only a login in this
// browser starts, and only forms that refuse cross-origin submissions
// write it. A parameter added to a crafted URL cannot stand in for it, and
// would change the request's key besides.
//
// An Interaction is read from the Login Session when it is loaded; what
// Finish changes is written by Save.
type Interaction struct {
	sessions *Sessions
	r        *http.Request // carries the loaded Login Session
	key      string

	auth               Authentication // with a nil EndUser if no one is signed in
	signedInForRequest bool
	decision           Decision

	finish bool // whether Save removes what is recorded for the request
}

// Interaction loads r's Login Session, or a new empty one, and returns
// what it records about the authorization request whose parameters,
// encoded as a query, are query: the same query the endpoint sends the
// browser to the login page and the consent form with.
func (s *Sessions) Interaction(r *http.Request, query string) (*Interaction, error) {
	r, err := s.load(r)
	if err != nil {
		return nil, err
	}
	i := &Interaction{sessions: s, r: r, key: requestKey(query)}
	ctx, m := r.Context(), s.manager
	// A Login Session for a Subject the registry no longer lists records
	// no authentication.
	u, ok := s.endUser(r)
	if !ok {
		return i, nil
	}
	i.auth = Authentication{EndUser: u, Time: time.Unix(m.GetInt64(ctx, authTimeKey), 0)}
	// The login time is auth_time, recorded with the login.
	i.signedInForRequest = m.GetString(ctx, loginForKey) == i.key && time.Since(i.auth.Time) < interactionLifetime
	decidedAt := time.Unix(m.GetInt64(ctx, decidedAtKey), 0)
	if m.GetString(ctx, decisionForKey) == i.key && time.Since(decidedAt) < interactionLifetime {
		i.decision = Decision(m.GetInt(ctx, decisionKey))
	}
	return i, nil
}

// Authentication returns the End-User's authentication, if the browser is
// signed in.
func (i *Interaction) Authentication() (Authentication, bool) {
	return i.auth, i.auth.EndUser != nil
}

// SignedInForRequest reports whether the End-User signed in on the login
// page for the request, as opposed to before it, within the last
// interactionLifetime.
func (i *Interaction) SignedInForRequest() bool {
	return i.signedInForRequest
}

// Decision returns what the End-User decided on the consent page for the
// request, within the last interactionLifetime.
func (i *Interaction) Decision() Decision {
	return i.decision
}

// Finish removes what the Login Session records about the request, once
// the authorization endpoint has answered it, with a code or an error, so
// that a later request with the same parameters starts again.
func (i *Interaction) Finish() {
	i.finish = true
}

// Save stores the Login Session, with what Finish changes, and writes its
// cookie to w. Every request changes the Login Session, since each moves
// its idle expiry. Save must be called before anything of the response is
// written.
func (i *Interaction) Save(w http.ResponseWriter) error {
	ctx, m := i.r.Context(), i.sessions.manager
	if i.finish {
		if m.GetString(ctx, loginForKey) == i.key {
			m.Remove(ctx, loginForKey)
		}
		if m.GetString(ctx, decisionForKey) == i.key {
			for _, k := range []string{decisionForKey, decisionKey, decidedAtKey} {
				m.Remove(ctx, k)
			}
		}
	}
	return i.sessions.save(w, i.r)
}

// decide records decision, made now, for the request whose parameters are
// query, in r's Login Session.
func (s *Sessions) decide(r *http.Request, query string, decision Decision) {
	ctx, m := r.Context(), s.manager
	m.Put(ctx, decisionForKey, requestKey(query))
	m.Put(ctx, decisionKey, int(decision))
	m.Put(ctx, decidedAtKey, time.Now().Unix())
}
