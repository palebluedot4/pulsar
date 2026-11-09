# OAuth 2.0 Form Post Response Mode

Clauses of [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)
(Final, 2015-04-27) that pulsar, as an authorization server, must or
should meet. All its normative text is in §2. It says nothing of error
responses; OpenID Connect Core 1.0 sends them by the Response Mode
requested (REQ-CORE-67).

- REQ-FORMPOST-1 (§2): "Authorization Response parameters are encoded as
  HTML form values that are auto-submitted in the User Agent, and thus are
  transmitted via the HTTP POST method to the Client, with the result
  parameters being encoded in the body using the
  application/x-www-form-urlencoded format."

  The form has one hidden input for each parameter, every value
  HTML-escaped, so that a `state` cannot add markup to the page.

  A browser can make an HTTP POST only to an `http` or `https` URI; one of
  another scheme, such as a native app's (RFC 8252 §7.1), it hands to the
  app that claims it, without a body. So `form_post` for such a redirect
  URI is refused with `invalid_request`, which RFC 6749 §4.1.2.1 defines
  for a request that "includes an invalid parameter value", sent by
  `query` with the request's other errors. The form-post pages of Keycloak
  (`OIDCRedirectUriBuilder.java`) and node-oidc-provider
  (`lib/response_modes/form_post.js`), at the commits
  `docs/research/logout-revocation-resources.md` lists, check no scheme
  before posting; the response then never reaches the Client.

- REQ-FORMPOST-2 (§2): "The action attribute of the form MUST be the
  Client's Redirection URI. The method of the form attribute MUST be POST."
- REQ-FORMPOST-3 (§2): "Because the Authorization Response is intended to
  be used only once, the Authorization Server MUST instruct the User Agent
  (and any intermediaries) not to store or reuse the content of the
  response."

  pulsar sends `Cache-Control: no-store`, as on its other pages.

- REQ-FORMPOST-4 (§2): "Any technique supported by the User Agent MAY be
  used to cause the submission of the form, and any form content necessary
  to support this MAY be included, such as submit controls and client-side
  scripting commands."

  A script submits the form when the page loads. The page keeps the login
  pages' Content-Security-Policy and allows that one script by its hash; a
  visible button submits the form when scripts are off.
