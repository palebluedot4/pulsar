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
	// post_logout_redirect_uri, with state added, if client registered it;
	// "" otherwise.
	redirectURI string
	// query is the parameters pulsar reads, encoded as a query, as the
	// confirmation form carries them.
	query string
}

// HandleLogout serves the logout endpoint, by GET and POST (OpenID Connect
// RP-Initiated Logout 1.0 §2). It asks the End-User, in every case, to
// confirm the logout, on a page whose form is submitted to the handler of
// HandleLogoutConfirmation; a request it cannot accept gets an error page
// instead.
//
// A Client sends the End-User here from its own site, so the endpoint, like
// the authorization endpoint, refuses no cross-origin request: it ends
// nothing itself.
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
		// A request a Client sends by POST from its own site arrives without
		// the SameSite=Lax Login Session cookie. It is sent back here by GET,
		// once, with the same parameters, as the authorization endpoint sends
		// one: a top-level navigation, on which the browser sends the cookie,
		// so that the page names the End-User signed in, and is shown for
		// them. 303, so that the browser retrieves it by GET.
		if r.Method == http.MethodPost && !p.sessions.HasCookie(r) {
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, LogoutPath(p.issuer)+"?"+req.query, http.StatusSeeOther)
			return
		}
		session, err := p.sessions.LogoutSession(r)
		if err != nil {
			p.logoutFailed(w, r, err)
			return
		}
		page := login.LogoutPage{Action: LogoutConfirmationPath(p.issuer) + "?" + req.query}
		if req.client != nil {
			page.ClientID = req.client.ID
		}
		if u, ok := session.EndUser(); ok {
			page.Subject, page.Username = u.Subject, u.Username
		}
		if err := session.Save(w); err != nil {
			p.logoutFailed(w, r, err)
			return
		}
		if err := login.WriteLogoutPage(w, page); err != nil {
			p.logoutFailed(w, r, err)
		}
	})
}

// HandleLogoutConfirmation serves the submission of the page the logout
// endpoint shows, by POST. The form's URL carries the logout request's
// parameters as its query, which are checked again, and its body the
// End-User's answer and the Subject of the End-User the page was shown
// for. If they confirmed, the Login Session ends, if there is one and it
// is still that End-User's; if they declined, it is kept. Either way, the
// browser is then sent to the Client's post-logout redirect URI, if the
// request identified the Client and the URI is one it registered, and
// shown a page that says whether they are signed out otherwise. If another
// End-User is signed in by then, nothing ends, and the browser is sent
// back to the logout endpoint to be asked again.
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
		params, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			p.errorPage(w, "The logout request could not be read.")
			return
		}
		req, msg := p.parseLogoutRequest(params)
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
		switch {
		case subject != form.Subject:
			// The page was shown for another End-User, or for none: ask again.
			// The query goes on unchanged to a fixed path on this origin, by
			// 303, so that the browser retrieves it by GET.
			if err := session.Save(w); err != nil {
				p.logoutFailed(w, r, err)
				return
			}
			http.Redirect(w, r, LogoutPath(p.issuer)+"?"+req.query, http.StatusSeeOther)
			return
		case form.Confirmed:
			err = session.End(w) //nolint:contextcheck // End uses the context of r, which LogoutSession keeps.
		default:
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
		if err := login.WriteLogoutOutcomePage(w, form.Confirmed); err != nil {
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
	if uri := params.Get("post_logout_redirect_uri"); uri != "" && req.client != nil && slices.Contains(req.client.PostLogoutRedirectURIs, uri) {
		req.redirectURI = uri
		if state := params.Get("state"); state != "" {
			req.redirectURI = withQuery(uri, url.Values{"state": {state}})
		}
	}
	kept := url.Values{}
	for _, name := range logoutParams {
		if v, ok := params[name]; ok {
			kept[name] = v
		}
	}
	req.query = kept.Encode()
	return req, ""
}

// idTokenHintClient returns the Client to which idToken was issued, if it
// is an ID token this OP issued: a JWT that one of the keys the JWK Set
// publishes signed, by RS256, the algorithm of the ID tokens it issues,
// whose typ is that of its ID tokens, whose iss is the issuer, and whose
// one audience is a registered Client (RP-Initiated Logout 1.0 §2).
//
// Its exp is not checked, so that an End-User returning after their ID
// token expired can still log out.
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
