package oidc

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/palebluedot4/pulsar/internal/login"
	"github.com/palebluedot4/pulsar/internal/registry"
)

// logoutConfirmationPath is where the logout confirmation form is
// submitted, relative to the issuer.
const logoutConfirmationPath = logoutPath + "/confirm"

// logoutParams are the parameters of a logout request that pulsar reads
// (OpenID Connect RP-Initiated Logout 1.0 §2). logout_hint and ui_locales
// are among those it ignores, as every other parameter is.
var logoutParams = []string{"id_token_hint", "client_id", "post_logout_redirect_uri", "state"}

// LogoutPath returns the path at which the logout endpoint for issuer is
// served: the path of the end_session_endpoint that the discovery document
// publishes.
func LogoutPath(issuer *Issuer) string {
	return issuer.Route(logoutPath)
}

// LogoutConfirmationPath returns the path, under issuer, to which the
// page the logout endpoint shows submits the End-User's answer.
func LogoutConfirmationPath(issuer *Issuer) string {
	return issuer.Route(logoutConfirmationPath)
}

// logoutRequest is a logout request whose parameters pulsar accepts.
type logoutRequest struct {
	// client is the Client the request is from, as its id_token_hint or
	// client_id identifies it, or nil if neither does.
	client *registry.Client
	// redirectURI is where the End-User is sent once they answer: the
	// post_logout_redirect_uri, as the Client registered it, with state
	// added; "" if the request names none the Client registered.
	redirectURI string
	// params are the parameters pulsar reads, each with its one value, as
	// the confirmation form carries them.
	params map[string]string
}

// HandleLogout serves the logout endpoint, by GET and POST (OpenID Connect
// RP-Initiated Logout 1.0 §2). It asks the End-User, in every case, to
// confirm the logout, on a page whose form is submitted to the handler of
// HandleLogoutConfirmation with the request's parameters in its body, so
// that no URL pulsar sends the browser to carries the id_token_hint; a
// request it cannot accept gets an error page instead.
//
// A Client sends the End-User here from its own site, so the endpoint, like
// the authorization endpoint, refuses no cross-origin request: it ends
// nothing itself. A request a Client sends by POST from its own site
// arrives without the SameSite=Lax Login Session cookie, so the page it
// gets names no End-User, and is shown for whoever is signed in when it is
// answered.
func (p *Provider) HandleLogout() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		params, err := readParams(w, r)
		if err != nil {
			p.errorPage(w, "The logout request could not be read.")
			return
		}
		req, msg := p.parseLogoutRequest(params)
		if msg != "" {
			p.errorPage(w, msg)
			return
		}
		known := r.Method != http.MethodPost || p.sessions.HasCookie(r)
		session, err := p.sessions.LogoutSession(r)
		if err != nil {
			p.logoutFailed(w, r, err)
			return
		}
		p.askToLogout(w, r, req, session, known)
	})
}

// askToLogout saves session and shows the page that asks the End-User to
// confirm req, for the End-User session signs in, or for no one, if known;
// for whoever is signed in when it is answered otherwise.
func (p *Provider) askToLogout(w http.ResponseWriter, r *http.Request, req logoutRequest, session *login.LogoutSession, known bool) {
	page := login.LogoutPage{
		Action:  LogoutConfirmationPath(p.issuer),
		Request: req.params,
		Known:   known,
	}
	if req.client != nil {
		page.ClientID = req.client.ID
	}
	if u, ok := session.EndUser(); ok && known {
		page.Subject, page.Username = u.Subject, u.Username
	}
	if err := session.Save(w); err != nil {
		p.logoutFailed(w, r, err)
		return
	}
	if err := login.WriteLogoutPage(w, page); err != nil {
		p.logoutFailed(w, r, err)
	}
}

// HandleLogoutConfirmation serves the submission of the page the logout
// endpoint shows, by POST. The form's body carries the logout request's
// parameters, which are checked again, the End-User's answer, and, unless
// the page was shown for whoever is signed in, the Subject of the End-User
// it was shown for.
//
// If another End-User is signed in than the one the page was shown for,
// or one is signed in and the page was shown for no one, nothing ends and
// the End-User signed in now is asked instead. Otherwise, if they
// confirmed, the Login Session ends; if they declined, it is kept; and if
// it has already ended, as it may while the page is open, the logout is
// done either way (RP-Initiated Logout 1.0 §4). The browser is then sent
// to the Client's post-logout redirect URI, if the request identified the
// Client and the URI is one it registered, and shown a page that says
// whether they are signed out otherwise.
//
// The form refuses cross-origin submissions, through
// [http.CrossOriginProtection], as the consent form does, so that another
// site cannot end an End-User's Login Session (RP-Initiated Logout 1.0 §6).
func (p *Provider) HandleLogoutConfirmation() http.Handler {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		form, ok := login.ReadLogoutForm(w, r)
		if !ok {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		req, msg := p.parseLogoutRequest(nonEmpty(form.Values))
		if msg != "" {
			p.errorPage(w, msg)
			return
		}
		session, err := p.sessions.LogoutSession(r)
		if err != nil {
			p.logoutFailed(w, r, err)
			return
		}
		var subject string
		if u, ok := session.EndUser(); ok {
			subject = u.Subject
		}
		if subject != "" && form.ShownFor != nil && *form.ShownFor != subject {
			p.askToLogout(w, r, req, session, true)
			return
		}
		signedOut := form.Confirmed || subject == ""
		if signedOut {
			// With no Login Session, this clears a cookie for one that ended.
			err = session.End(w) //nolint:contextcheck // End uses the context of r, which LogoutSession keeps.
		} else {
			err = session.Save(w)
		}
		if err != nil {
			p.logoutFailed(w, r, err)
			return
		}
		if req.redirectURI != "" {
			// 303, so that the browser retrieves it by GET, as RFC 9700 §4.12
			// advises after a POST.
			http.Redirect(w, r, req.redirectURI, http.StatusSeeOther)
			return
		}
		if err := login.WriteLogoutOutcomePage(w, signedOut); err != nil {
			p.logoutFailed(w, r, err)
		}
	})
	return http.NewCrossOriginProtection().Handler(h)
}

// parseLogoutRequest checks the parameters of a logout request, and returns
// the request, or the message of the error page to show instead.
//
// A request that does not identify its Client, or names a
// post_logout_redirect_uri that Client did not register, is accepted: it
// only redirects nowhere (RP-Initiated Logout 1.0 §3, §4).
func (p *Provider) parseLogoutRequest(params url.Values) (req logoutRequest, msg string) {
	if name, ok := repeated(params, logoutParams); ok {
		return req, "The parameter " + name + " is repeated."
	}
	if hint := params.Get("id_token_hint"); hint != "" {
		client, ok := p.idTokenHintClient(hint)
		if !ok {
			return req, "The id_token_hint is not an ID token this OP issued to a registered client."
		}
		req.client = client
	}
	// A client_id that names another Client than the hint fails validation,
	// and is not used (§2, §4): the request then identifies no Client.
	if id := params.Get("client_id"); id != "" {
		switch {
		case req.client == nil:
			req.client, _ = p.registry.Client(id)
		case req.client.ID != id:
			req.client = nil
		}
	}
	if req.client != nil {
		// The registered URI, which the request's equals, is the one
		// redirected to.
		if i := slices.Index(req.client.PostLogoutRedirectURIs, params.Get("post_logout_redirect_uri")); i >= 0 {
			req.redirectURI = req.client.PostLogoutRedirectURIs[i]
			if state := params.Get("state"); state != "" {
				req.redirectURI = withQuery(req.redirectURI, url.Values{"state": {state}})
			}
		}
	}
	req.params = make(map[string]string)
	for _, name := range logoutParams {
		if v := params.Get(name); v != "" {
			req.params[name] = v
		}
	}
	return req, ""
}

// idTokenHintClient returns the Client to which idToken was issued, if it
// is an ID token this OP issued: a JWT that one of the keys the JWK Set
// publishes signed, by RS256, the algorithm of the ID tokens it issues,
// whose typ is that of its ID tokens, whose iss is the issuer, and whose
// one audience is a registered Client (RP-Initiated Logout 1.0 §2).
//
// Its exp is not checked, so that an End-User returning after their ID
// token expired can still log out. A hint signed by a key the JWK Set no
// longer publishes, after a rotation, is refused all the same.
func (p *Provider) idTokenHintClient(idToken string) (*registry.Client, bool) {
	typ, payload, ok := p.keys.VerifyJWT(idToken)
	// The media type, compared without regard to case (RFC 7515 §4.1.9), so
	// that no access token stands in for an ID token (RFC 8725 §3.11).
	if !ok || !strings.EqualFold(typ, "JWT") {
		return nil, false
	}
	var claims jwt.Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, false
	}
	if claims.Issuer != p.issuer.String() || len(claims.Audience) != 1 {
		return nil, false
	}
	return p.registry.Client(claims.Audience[0])
}

// withQuery returns uri with params added to any query it has, which is
// kept as registered.
func withQuery(uri string, params url.Values) string {
	sep := "?"
	switch {
	case strings.HasSuffix(uri, "?") || strings.HasSuffix(uri, "&"):
		sep = ""
	case strings.Contains(uri, "?"):
		sep = "&"
	}
	return uri + sep + params.Encode()
}

// logoutFailed logs err, a failure of pulsar's own, and answers 500.
func (p *Provider) logoutFailed(w http.ResponseWriter, r *http.Request, err error) {
	p.logger.ErrorContext(r.Context(), "logout", "error", err)
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}
