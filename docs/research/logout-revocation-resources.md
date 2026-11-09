# Form Post, RP-Initiated Logout, token revocation and Resource Indicators

Surveyed 2026-11-09 for #69, the specification of form_post, RP-Initiated
Logout and token revocation, and #70, that of Resource Indicators. It covers
these questions: what the conformance suite's Form Post and RP-Initiated
Logout plans send and expect; what RP-Initiated Logout 1.0, the Form Post
Response Mode, RFC 7009 and RFC 8707 require of an OP; whether logout should
end refresh tokens and access tokens; what revoking one token should revoke
with it, and for which Clients; what CORS the revocation endpoint answers
with; and how a `resource` is registered, validated and turned into an
audience.

The OpenID conformance suite was read at `release-v5.3.4`, commit
`23353b36957d6466010de767c812d2c91ed37638` (2026-10-26), with paths under
`src/main/java/net/openid/conformance/`. Open-source providers were read from
their source at these commits:

- node-oidc-provider 9.13.3, `3ed87bef95d0f02b72917b9eb7d17ef5c3b2313b`
  (2026-11-04)
- Ory Hydra `master`, `4174065ffb052799890f7480f5360a877a67ffc1`
  (2026-07-29), which now vendors fosite as `fosite/`; the latest release in
  its CHANGELOG is v26.2.0
- Keycloak `main`, `e649c7732498971ddc8254e9a9f2b65428aa8b17` (2026-11-09,
  version 999.0.0-SNAPSHOT)
- Spring Authorization Server, now in Spring Security `main`
  (7.2.0-SNAPSHOT), `fc7249dc7afba47d30dd1877d0634401b1fd98da` (2026-11-05),
  module `oauth2/oauth2-authorization-server`, with paths under
  `src/main/java/org/springframework/security/oauth2/server/authorization/`

These are development heads, not releases, and a released version may behave
differently (**UNVERIFIED** that each behaves the same). Paths are relative
to each repository at its commit. OAuth 2.1 was read as
draft-ietf-oauth-v2-1-17 (2026-10-31), which is still a draft. Anything not
confirmed is marked **UNVERIFIED**.

## The conformance suite at release-v5.3.4

### The Form Post Basic plan

`oidcc-formpost-basic-certification-test-plan` is certifiable, with the
profile name "Form Post OP".

| What               | Detail                                                                                                                                                                                                                                                                                                                    | Source                                                                                 |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| Modules            | The Basic OP plan's modules, in the same order and with the same `client_secret_basic` and `client_secret_post` split, with every `ResponseMode` variant replaced by `form_post`.                                                                                                                                         | `openid/OIDCCFormPostBasicTestPlan.java`, `openid/AbstractFormPostTestPlan.java`       |
| Request            | Every authorization request sends `response_mode=form_post`.                                                                                                                                                                                                                                                              | `openid/AbstractOIDCCServerTest.java` (`CreateAuthorizationRequestSteps`)              |
| Callback           | Each a FAILURE if it fails: the method is `POST`; the media type is `application/x-www-form-urlencoded`, parameters such as `charset` ignored; the URL query has no `code`; the URL query has no `error`. The response parameters are then read from the POST body.                                                       | `openid/AbstractOIDCCServerTest.java` (`processCallback`)                              |
| Errors             | Errors too must come by form_post. `oidcc-response-type-missing` reads its error from the POST body after the same four checks, and so does every module that expects an error at the callback, such as `oidcc-prompt-none-not-logged-in`, since they share `processCallback`.                                            | `openid/OIDCCResponseTypeMissing.java`, `openid/AbstractOIDCCServerTest.java`          |
| Discovery          | No OP plan checks `response_modes_supported` for `form_post`. The only OP-side check of that key is `CheckDiscEndpointResponseModesSupportedContainsJwt`, for JARM.                                                                                                                                                       | `condition/client/`                                                                    |
| Browser automation | HtmlUnit with JavaScript enabled, and script errors do not throw. The callback URL is unchanged, so `config-basic.json`'s "Verify Complete" task, which matches `.../callback*` and waits for `submission_complete`, still matches the form's POST; the suite answers a POST to the callback with the same page as a GET. | `frontchannel/BrowserControl.java`, `testmodule/AbstractRedirectServerTestModule.java` |

pulsar's login pages are served with
`Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
(`internal/login/login.go`). In CSP Level 3, "The default-src directive
serves as a fallback for the other fetch directives" (§6.1.3), and
`form-action` is a navigation directive (§6.4.1), not a fetch directive. So
that policy blocks an inline script, an `onload` handler among them, but not
the form's submission. Whether HtmlUnit enforces CSP is **UNVERIFIED**; an
auto-submitting page that works under pulsar's CSP needs a nonce or a hash
for its script, or a visible submit button as a fallback.

### The RP-Initiated Logout plan

`oidcc-rp-initiated-logout-certification-test-plan` is certifiable, with the
profile name "RP-Initiated OP". Its discovery module runs with
`ServerMetadata=discovery`; the other ten with `ServerMetadata=discovery`,
`ClientAuthType=client_secret_basic` and `ResponseMode=default`.
`ClientRegistration` is left to the run, which for pulsar would be
`static_client`.

Every module but the discovery one starts the same way
(`openid/AbstractOIDCCRpInitiatedLogout.java`):

1. A code flow, with a `state` 128 characters long ("use a longer state
   value to check OP doesn't corrupt it").
2. A request to `end_session_endpoint` built from `id_token_hint`,
   `post_logout_redirect_uri` and `state` alone, in the query string, which
   the browser follows by GET. The suite never sends `client_id`,
   `logout_hint` or `ui_locales`, and never sends a POST.
3. The `post_logout_redirect_uri` is the test's base URL plus
   `/post_logout_redirect`; with the current configuration,
   `https://localhost.emobix.co.uk:8443/test/a/pulsar/post_logout_redirect`.
   The module summary: "If using static client registration you must
   register a post_logout_redirect_uri, the same url as the redirect url but
   replacing the portion after the alias with '/post_logout_redirect'."
4. In the two modules that expect a redirect back, a second authorization
   request with `prompt=none` must get `interaction_required`,
   `login_required`, `account_selection_required` or `consent_required`, a
   FAILURE otherwise. So the logout must end pulsar's Login Session.

| Module                                                              | Sent                                                                                                                                   | Expected                                                                                                                                                                              | Result for a correct OP                  |
| ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| `oidcc-rp-initiated-logout-discovery-endpoint-verification`         | Nothing                                                                                                                                | Every key ending `_endpoint` is https, and `end_session_endpoint` is a valid https URL; each a FAILURE                                                                                | PASSED                                   |
| `oidcc-rp-initiated-logout`                                         | Hint, URI, `state`                                                                                                                     | A redirect to the URI with `state` unchanged (FAILURE); any parameter but `state` a WARNING; then `prompt=none` must fail                                                             | PASSED, or WARNING with extra parameters |
| `oidcc-rp-initiated-logout-no-state`                                | Hint, URI                                                                                                                              | A redirect with no `state` (FAILURE); extra parameters a WARNING; then `prompt=none` must fail                                                                                        | PASSED                                   |
| `oidcc-rp-initiated-logout-bad-post-logout-redirect-uri`            | Hint, an unregistered URI, `state`                                                                                                     | "The OP must not redirect back and must either show an error screen or confirm with the user if they want to logout"; placeholder `ExpectPostLogoutRedirectUriNotRegisteredErrorPage` | REVIEW                                   |
| `oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri` | Hint, the registered URI with `?foo=bar`, `state`                                                                                      | The same: the match must be exact                                                                                                                                                     | REVIEW                                   |
| `oidcc-rp-initiated-logout-modified-id-token-hint`                  | A hint re-headed `{"alg": "none"}` with its signature dropped, URI, `state`                                                            | No redirect; an error page or a confirmation; placeholder `ExpectInvalidIdTokenHintErrorPage`                                                                                         | REVIEW                                   |
| `oidcc-rp-initiated-logout-bad-id-token-hint`                       | A hint forged by the suite, with `iss` the `client_id`, `aud` the issuer, signed HS256 with a key from the client secret; URI, `state` | The same                                                                                                                                                                              | REVIEW                                   |
| `oidcc-rp-initiated-logout-no-id-token-hint`                        | URI, `state`; no hint and no `client_id`                                                                                               | No redirect; an error page or a confirmation; placeholder `ExpectIdTokenHintRequiredErrorPage`                                                                                        | REVIEW                                   |
| `oidcc-rp-initiated-logout-no-post-logout-redirect-uri`             | Hint, `state`                                                                                                                          | "the OP must log the user out, a screenshot of the 'you are logged out' screen should be uploaded"; `ExpectSuccessfulLogoutPage`                                                      | REVIEW                                   |
| `oidcc-rp-initiated-logout-only-state`                              | `state`                                                                                                                                | The same                                                                                                                                                                              | REVIEW                                   |
| `oidcc-rp-initiated-logout-no-params`                               | Nothing                                                                                                                                | The same                                                                                                                                                                              | REVIEW                                   |

In every module but the two that expect a redirect, a request to
`/post_logout_redirect` fails the test ("OP has incorrectly called the
registered post_logout_redirect_uri..."). Those eight modules end when their
placeholder is filled; they do not check by `prompt=none` that the logout
happened.

The confirmation page and browser automation:

- `BrowserControl.goToUrl` automates a page only if a configured
  `browser[].match` pattern matches its URL; otherwise "the url is made
  available for user interaction" and the module waits, which would hang an
  unattended run. `conformance/config-basic.json` matches only
  `https://pulsar:9443/authorize*`, so the logout plan needs a configuration
  with an entry that matches pulsar's `end_session_endpoint`.
- A task can `click` by XPath, enter `text` into fields, and `wait` for text
  with `update-image-placeholder` or `update-image-placeholder-optional`,
  which records the page's HTML in the module's placeholder. A task marked
  `"optional": true` is skipped when the current URL does not match. So the
  automation can click through a confirmation page, and an optional confirm
  task lets the modules that redirect at once still run.
- All the browser sessions of one module share one cookie manager ("This is
  necessary for OIDC prompt=login tests"), so the Login Session cookie from
  the code flow reaches the `end_session_endpoint` and the later
  `prompt=none` request.
- A per-module `override`, which `config-basic.json` already uses, can give
  the error-page modules their own `wait` text.

No module reads `sid`, sends an expired `id_token_hint`, or uses
`frontchannel_logout_*`, `backchannel_logout_*` or `check_session_iframe`;
those belong to the Front-Channel, Back-Channel and Session Management
plans. The new discovery keys would not warn in the Config OP plan:
`CheckForUnexpectedParametersInServerMetadata` validates against the
RFC 8414 schema in
`src/main/resources/json-schemas/rfc8414/oauth_authorization_server_metadata.json`,
whose properties include `end_session_endpoint`, `revocation_endpoint` and
`revocation_endpoint_auth_methods_supported`.

### No plan tests RFC 7009

No OP plan tests token revocation. A search of `src/main` for
`revocation_endpoint`, `RFC7009` and `token_type_hint` finds only the RFC 8414
metadata schema and `CreateIntrospectionRequestForRefreshToken.java`, which
is for introspection. The Basic plan's "OP-OAuth-2nd-Revokes" is about
revoking tokens on a reused code, not RFC 7009.

Sources: <https://gitlab.com/openid/conformance-suite/-/tree/release-v5.3.4/src/main/java/net/openid/conformance/>,
in particular `openid/OIDCCFormPostBasicTestPlan.java`,
`openid/OIDCCRpInitiatedLogoutTestPlan.java`,
`openid/AbstractOIDCCRpInitiatedLogout.java`, each module's file, the
conditions under `condition/client/`, and `frontchannel/BrowserControl.java`.

## RP-Initiated Logout 1.0

What OpenID Connect RP-Initiated Logout 1.0 (Final, 2022-09-12) says of the
OP:

| Clause | Topic                      | What it says                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ------ | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| §2     | `id_token_hint`            | "RECOMMENDED. ID Token previously issued by the OP to the RP passed to the Logout Endpoint as a hint about the End-User's current authenticated session with the Client."                                                                                                                                                                                                                                                       |
| §2     | `logout_hint`              | "OPTIONAL. ... The value and meaning of this parameter is left up to the OP's discretion."                                                                                                                                                                                                                                                                                                                                      |
| §2     | `client_id`                | "OPTIONAL. ... When both client_id and id_token_hint are present, the OP MUST verify that the Client Identifier matches the one used when issuing the ID Token. The most common use case for this parameter is to specify the Client Identifier when post_logout_redirect_uri is used but id_token_hint is not."                                                                                                                |
| §2     | `post_logout_redirect_uri` | "OPTIONAL. ... The value MUST have been previously registered with the OP, either using the post_logout_redirect_uris Registration parameter or via another mechanism. An id_token_hint is also RECOMMENDED when this parameter is included." It "SHOULD use the https scheme", and "MAY use the http scheme, provided that the Client Type is confidential".                                                                   |
| §2     | `state`                    | "OPTIONAL. ... If included in the logout request, the OP passes this value back to the RP using the state parameter when redirecting the User Agent back to the RP."                                                                                                                                                                                                                                                            |
| §2     | `ui_locales`               | "OPTIONAL. ... An error SHOULD NOT result if some or all of the requested locales are not supported by the OpenID Provider."                                                                                                                                                                                                                                                                                                    |
| §2     | Methods                    | "OpenID Providers MUST support the use of the HTTP GET and POST methods ... at the Logout Endpoint." GET uses query string serialization, POST form serialization.                                                                                                                                                                                                                                                              |
| §2     | Validating the hint        | "When an id_token_hint parameter is present, the OP MUST validate that it was the issuer of the ID Token. The OP SHOULD accept ID Tokens when the RP identified by the ID Token's aud claim and/or sid claim has a current session or had a recent session at the OP, even when the exp time has passed." A `sid` that matches no current or recent session makes the request suspect, and the OP "MAY decline to act upon it". |
| §2     | Confirmation               | "At the Logout Endpoint, the OP SHOULD ask the End-User whether to log out of the OP as well. Furthermore, the OP MUST ask the End-User this question if an id_token_hint was not provided or if the supplied ID Token does not belong to the current OP session with the RP and/or currently logged in End-User. If the End-User says "yes", then the OP MUST log out the End-User."                                           |
| §2     | Notifying RPs              | The OP "uses the logout mechanism(s) registered by the RPs to notify any RPs logged in as that End-User", meaning Session Management, Front-Channel or Back-Channel Logout. With none registered, there is no one to notify.                                                                                                                                                                                                    |
| §2.1   | Discovery                  | "This OpenID Provider Metadata parameter MUST be included in the Server's discovery responses when RP-Initiated Logout and Discovery are supported: end_session_endpoint REQUIRED. ... This URL MUST use the https scheme and MAY contain port, path, and query parameter components."                                                                                                                                          |
| §3     | Redirection                | If `id_token_hint` "is not supplied with post_logout_redirect_uri, the OP MUST NOT perform post-logout redirection unless the OP has other means of confirming the legitimacy of the post-logout redirection target. The OP also MUST NOT perform post-logout redirection if the post_logout_redirect_uri value supplied does not exactly match one of the previously registered post_logout_redirect_uris values."             |
| §3.1   | Registration               | "post_logout_redirect_uris OPTIONAL. Array of URLs supplied by the RP to which it MAY request that the End-User's User Agent be redirected". They "SHOULD use the https scheme", and may use http only for a confidential Client "and provided the OP allows the use of http RP URIs".                                                                                                                                          |
| §4     | Validation and errors      | Information that fails validation "MUST NOT be used". "it is explicitly not an error for an RP to request that a logout be performed when the OP does not consider that the End-User is logged in with the OP at the requesting RP." On an error, "the OP MUST not perform post-logout redirection to an RP"; beyond that, "It MAY display an error message. It MAY ask the End-User whether to log out of the OP."             |
| §6     | Security                   | "Logout requests without a valid id_token_hint value are a potential means of denial of service; therefore, OPs should obtain explicit confirmation from the End-User before acting upon them."                                                                                                                                                                                                                                 |

On an expired `id_token_hint`, the specification says only the SHOULD in §2:
accept it despite `exp` when the RP has a current or recent session. It
states no other rule for validating the hint beyond "MUST validate that it
was the issuer".

Source: <https://openid.net/specs/openid-connect-rpinitiated-1_0.html>.

## Form Post Response Mode

All the normative text of OAuth 2.0 Form Post Response Mode (Final,
2015-04-27) is in §2:

| Topic      | What it says                                                                                                                                                                                                                                                                                                                                                  |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Encoding   | "Authorization Response parameters are encoded as HTML form values that are auto-submitted in the User Agent, and thus are transmitted via the HTTP POST method to the Client, with the result parameters being encoded in the body using the application/x-www-form-urlencoded format."                                                                      |
| The form   | "The action attribute of the form MUST be the Client's Redirection URI. The method of the form attribute MUST be POST."                                                                                                                                                                                                                                       |
| Caching    | "Because the Authorization Response is intended to be used only once, the Authorization Server MUST instruct the User Agent (and any intermediaries) not to store or reuse the content of the response."                                                                                                                                                      |
| Submission | "Any technique supported by the User Agent MAY be used to cause the submission of the form, and any form content necessary to support this MAY be included, such as submit controls and client-side scripting commands. However, the Client MUST be able to process the message without regard for the mechanism by which the form submission was initiated." |

§4 adds that "it is safe to return Authorization Response parameters whose
default Response Modes are the query encoding or the fragment encoding using
the form_post Response Mode." The non-normative example in Appendix A sends
`Content-Type: text/html;charset=UTF-8`, `Cache-Control: no-cache, no-store`
and `Pragma: no-cache`, with `<body onload="javascript:document.forms[0].submit()">`
and a hidden input per parameter.

The Form Post specification says nothing of error responses. The rules come
from elsewhere:

- OpenID Connect Core 1.0 §3.1.2.6: "When using the Authorization Code Flow,
  the error response parameters are added to the query component of the
  Redirection URI, unless a different Response Mode was specified." §3.1.2.5
  says the same of the success response.
- OAuth 2.0 Multiple Response Type Encoding Practices §2.1: using
  `response_mode` "is NOT RECOMMENDED with a value that specifies the same
  Response Mode as the default Response Mode for the Response Type used."
  §2.2, for response types of several values: "All parameters returned from
  the Authorization Endpoint SHOULD use the same Response Mode. This
  recommendation applies to both success and error responses."
- OpenID Connect Discovery 1.0 §3: "response_modes_supported OPTIONAL. JSON
  array containing a list of the OAuth 2.0 response_mode values that this OP
  supports ... If omitted, the default for Dynamic OpenID Providers is
  ["query", "fragment"]."

Today pulsar refuses any `response_mode` but `query` with `invalid_request`,
and checks it after `response_type` (`internal/oidc/authorize.go`); discovery
lists `response_modes_supported: ["query"]` (`internal/oidc/discovery.go`).

Sources: <https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html>,
<https://openid.net/specs/openid-connect-core-1_0.html>,
<https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html>,
<https://openid.net/specs/openid-connect-discovery-1_0.html>,
<https://www.w3.org/TR/CSP3/>.

## Token revocation

### RFC 7009

| Clause | Topic                 | What it says                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ------ | --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| §1     | Scope                 | "A revocation request will invalidate the actual token and, if applicable, other tokens based on the same authorization grant and the authorization grant itself."                                                                                                                                                                                                                                                                                                                  |
| §2     | Token types           | "Implementations MUST support the revocation of refresh tokens and SHOULD support the revocation of access tokens (see Implementation Note)."                                                                                                                                                                                                                                                                                                                                       |
| §2     | Transport             | An "HTTP POST request to the token revocation endpoint URL". "URLs for token revocation endpoints MUST be HTTPS URLs." A server also reachable over HTTP "SHOULD also offer a revocation service at the corresponding HTTP URI, but it MUST NOT publish this URI as a token revocation endpoint."                                                                                                                                                                                   |
| §2.1   | Request               | `token` is REQUIRED. `token_type_hint` is OPTIONAL, `access_token` or `refresh_token`: "If the server is unable to locate the token using the given hint, it MUST extend its search across all of its supported token types. An authorization server MAY ignore this parameter, particularly if it is able to detect the token type automatically."                                                                                                                                 |
| §2.1   | Client authentication | "The client also includes its authentication credentials as described in Section 2.3. of [RFC6749]." "The authorization server first validates the client credentials (in case of a confidential client) and then verifies whether the token was issued to the client making the revocation request. If this validation fails, the request is refused and the client is informed of the error by the authorization server as described below."                                      |
| §2.1   | Effect                | "The invalidation takes place immediately, and the token cannot be used again after the revocation." "If the particular token is a refresh token and the authorization server supports the revocation of access tokens, then the authorization server SHOULD also invalidate all access tokens based on the same authorization grant (see Implementation Note). If the token passed to the request is an access token, the server MAY revoke the respective refresh token as well." |
| §2.2   | Response              | "The authorization server responds with HTTP status code 200 if the token has been revoked successfully or if the client submitted an invalid token." "An invalid token type hint value is ignored by the authorization server and does not influence the revocation response."                                                                                                                                                                                                     |
| §2.2.1 | Errors                | "The error presentation conforms to the definition in Section 5.2 of [RFC6749]", plus `unsupported_token_type`: "the client tried to revoke an access token on a server not supporting this feature." On a 503 the client "must assume the token still exists".                                                                                                                                                                                                                     |
| §2.3   | CORS                  | "The revocation endpoint MAY support Cross-Origin Resource Sharing (CORS) [W3C.WD-cors-20120403] if it is aimed at use in combination with user-agent-based applications." It MAY also offer JSONP.                                                                                                                                                                                                                                                                                 |
| §3     | Implementation Note   | Revoking self-contained access tokens needs "some (currently non-standardized) backend interaction"; the alternative is to "issue short-lived access tokens".                                                                                                                                                                                                                                                                                                                       |
| §5     | Security              | "If the authorization server does not support access token revocation, access tokens will not be immediately invalidated when the corresponding refresh token is revoked. Deployments must take this into account". "a client's request must contain a valid client_id, in the case of a public client, or valid client credentials, in the case of a confidential client. The token being revoked must also belong to the requesting client."                                      |

So revoking access tokens is a SHOULD, and a refresh token's revocation
SHOULD reach the grant's access tokens only if the server "supports the
revocation of access tokens". RFC 7009 names no error code for a token that
belongs to another Client; §2.1 says only that the request is refused, with
an error as §2.2.1 describes.

### Related clauses

- RFC 8414 §2: "revocation_endpoint OPTIONAL. URL of the authorization
  server's OAuth 2.0 revocation endpoint [RFC7009]."
  "revocation_endpoint_auth_methods_supported OPTIONAL. JSON array
  containing a list of client authentication methods supported by this
  revocation endpoint. ... If omitted, the default is
  "client_secret_basic"". `revocation_endpoint_auth_signing_alg_values_supported`
  "MUST be present if either of these authentication methods are specified",
  meaning `private_key_jwt` and `client_secret_jwt`. Listing `none` is how a
  server would advertise public Clients there; that any specification
  requires it is **UNVERIFIED**.
- RFC 9700 §4.14.2: "Authorization servers MAY revoke refresh tokens
  automatically in case of a security event, such as: password change or
  logout at the authorization server." Also: "If refresh tokens are issued,
  those refresh tokens MUST be bound to the scope and resource servers as
  consented by the resource owner." RFC 9700 does not cite RFC 7009.
- OAuth 2.1 draft -17:
  - §3.2: where a browser-based application accesses the authorization
    server's other endpoints, "such as metadata URLs, dynamic client
    registration, revocation, introspection, discovery, or user info
    endpoints", they "MUST also send the CORS header fields to allow
    access."
  - §4.3.3 repeats RFC 9700's MAY on revoking refresh tokens at logout.
  - §7.9: "Authorization servers SHOULD allow administrators and resource
    owners to view the set of clients that have been granted access to their
    resources and to revoke those grants (see [RFC7009])".
  - §9.3.2, Refresh Tokens for Browser-Based Applications: "Authorization
    servers SHOULD link the lifetime of the refresh token to the user's
    authenticated session with the authorization server, so that when the
    user logs out, previously issued refresh tokens become invalid.
    Authorization servers MAY set different policies for refresh token
    issuance, lifetime, and expiration for browser-based applications
    compared to other public clients."
  - §9.3.4: "The authorization server and resource server MUST send the
    necessary CORS ... header fields to enable the app to make these
    requests".
  - Appendix D lists RFC 7009 as an extension, "a mechanism for clients to
    indicate to the authorization server that an access token is no longer
    needed."

Sources: <https://www.rfc-editor.org/rfc/rfc7009>,
<https://www.rfc-editor.org/rfc/rfc8414>,
<https://www.rfc-editor.org/rfc/rfc9700>,
<https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-17.txt>.

## Resource Indicators and audience restriction

### RFC 8707

| Clause | Topic                 | What it says                                                                                                                                                                                                                                                                                                                                                                                                               |
| ------ | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| §2     | `resource`            | "Its value MUST be an absolute URI, as specified by Section 4.3 of [RFC3986]. The URI MUST NOT include a fragment component. It SHOULD NOT include a query component ... Multiple "resource" parameters MAY be used to indicate that the requested token is intended to be used at multiple resources."                                                                                                                    |
| §2     | `invalid_target`      | "The requested resource is invalid, missing, unknown, or malformed." It "can also be used to inform the client that it has requested an invalid combination of resource and scope."                                                                                                                                                                                                                                        |
| §2     | Audience              | "The authorization server SHOULD audience-restrict issued access tokens to the resource(s) indicated by the "resource" parameter. ... The authorization server may use the exact "resource" value as the audience or it may map from that value to a more general URI or abstract identifier for the given resource."                                                                                                      |
| §2.1   | Authorization request | In the code flow, "the requested resource is applicable to the full authorization grant." Without `resource`, the server "MAY process the request with no specific resource or by using a predefined default resource value", or "MAY fail requests that omit the parameter with an "invalid_target" error". A value it cannot parse or accept "should" be rejected with `invalid_target`.                                 |
| §2.2   | Token request         | The acceptable values are "at its sole discretion based on local policy or configuration", and for `refresh_token` and `authorization_code` "may limit the acceptable resources to those that were originally granted by the resource owner or a subset thereof." For a subset at the code exchange, the access token covers the subset, "whereas any refresh token that is returned is bound to the full original grant." |
| §2.2   | Scope                 | "the requested access rights of the token are the cartesian product of all the scopes at all the target services." The server "should downscope", and "must indicate the access token's effective scope to the client in the "scope" response parameter value when it differs from the scope requested".                                                                                                                   |
| §3     | Security              | "using only a single "resource" parameter is encouraged. If a bearer token has multiple intended recipients (audiences), then the token is valid at more than one protected resource and can be used by any one of those resources to access any of the others." Also: "an authorization server may be unwilling or unable to fulfill a token request with multiple resources."                                            |
| §5.2   | IANA                  | `invalid_target` is registered for the "implicit grant error response, token error response"; the code flow's authorization error response is not listed, though §2.1 says to reject with it.                                                                                                                                                                                                                              |

### RFC 9700 §2.3

"Access Token Privilege Restriction" asks that the privileges of an access
token "SHOULD be restricted to the minimum required for the particular
application or use case", and:

> In particular, access tokens SHOULD be audience-restricted to a specific
> resource server or, if that is not feasible, to a small set of resource
> servers. To put this into effect, the authorization server associates the
> access token with certain resource servers, and every resource server is
> obliged to verify, for every request, whether the access token sent with
> that request was meant to be used for that particular resource server. If
> it was not, the resource server MUST refuse to serve the respective
> request. The aud claim as defined in [RFC9068] MAY be used to
> audience-restrict access tokens. Clients and authorization servers MAY
> utilize the parameters scope or resource as specified in [RFC6749] and
> [RFC8707], respectively, to determine the resource server they want to
> access.

Audience restriction is a SHOULD for the authorization server; the only MUST
is the resource server's refusal. §4.10.2 adds: "In deployments where the
authorization server knows the URLs of all resource servers, the
authorization server may just refuse to issue access tokens for unknown
resource server URLs", and to prevent phishing "it is necessary to use the
actual URL the client will send requests to." §4.10 says that audience
restriction "SHOULD be used to prevent replay of captured access tokens on
other resource servers."

### RFC 9068

- §2.2: "aud REQUIRED".
- §3: "If the request includes a "resource" parameter (as defined in
  [RFC8707]), the resulting JWT access token "aud" claim SHOULD have the same
  value as the "resource" parameter in the request." "If the request does
  not include a "resource" parameter, the authorization server MUST use a
  default resource indicator in the "aud" claim." It SHOULD infer that
  default from `scope`, and SHOULD reject with `invalid_scope` scopes that
  point to different defaults. pulsar records this as REQ-AT-5, with the
  issuer as the default (`docs/requirements/rfc9068.md`).
- §4: "The resource server MUST validate that the "aud" claim contains a
  resource indicator value corresponding to an identifier the resource
  server expects for itself."
- §5: with several resource indicators, "the authorization server should
  ensure that each scope string included in the resulting JWT access token,
  if any, can be unambiguously correlated to a specific resource among the
  ones listed in the "aud" claim."

Sources: <https://www.rfc-editor.org/rfc/rfc8707>,
<https://www.rfc-editor.org/rfc/rfc9700#section-2.3>,
<https://www.rfc-editor.org/rfc/rfc9068>.

## What other providers do

The four providers were read at the development heads listed above, not at
releases.

### Logout and refresh tokens

| Provider           | Confirmation                                                                  | Refresh tokens at logout                                                                                                                                                                                                                                               | Access tokens at logout                                                                                                                                                                                                  | Source                                                                                                                                                   |
| ------------------ | ----------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| node-oidc-provider | Always, when the session has an account; without one the form posts itself.   | On "yes", each Client's grant in the session is revoked unless it persists logout, which by default means unless it has `offline_access` ("Drop the grants without offline_access"). Refresh tokens are issued only with `offline_access` by default, so they survive. | Revoked with their grant, unless the grant has `offline_access`.                                                                                                                                                         | `lib/actions/end_session.js`, `lib/helpers/defaults.js` (`expiresWithSession`, `issueRefreshToken`), `lib/helpers/revoke.js`                             |
| Keycloak           | Not surveyed.                                                                 | The user session is removed. "Online refresh tokens cannot be used once logout begins for the user session"; "The offline token is valid after a user logout."                                                                                                         | UserInfo and introspection look up the token's user session first, as the [earlier survey](refresh-tokens.md#an-end-user-removed-after-a-grant) found at 26.8.2, so an online session's access tokens are refused there. | `docs/documentation/server_admin/topics/sessions/offline.adoc`, `protocol/oidc/endpoints/LogoutEndpoint.java`                                            |
| Ory Hydra          | Not surveyed.                                                                 | Kept. Logout deletes the login session's row and cookie and runs front- and back-channel logout; the flow's reference to the login session is `ON DELETE SET NULL`, and tokens hang off the flow, regardless of `offline_access` or Client type.                       | Kept, for the same reason.                                                                                                                                                                                               | `consent/strategy_default.go`, `persistence/sql/persister_consent.go`, `persistence/sql/migrations/20221109000010000000_fix_foreign_key.postgres.up.sql` |
| Spring AS          | None. `id_token_hint` is required, and "Expired ID Token should be accepted". | Kept: logout ends the HTTP session, and nothing in the logout path touches `OAuth2AuthorizationService`.                                                                                                                                                               | Kept, for the same reason.                                                                                                                                                                                               | `oidc/authentication/OidcLogoutAuthenticationProvider.java`, `oidc/web/authentication/OidcLogoutAuthenticationSuccessHandler.java`                       |

All four keep offline tokens through logout: node-oidc-provider and Keycloak
end only the others, and Hydra and Spring end none. On access tokens they
split 2–2: node-oidc-provider and Keycloak end those of the online grant or
session, Hydra and Spring keep them all. None of the four treats
browser-based applications differently by default, so none follows OAuth 2.1
§9.3.2. node-oidc-provider also drops, without an error, a
`post_logout_redirect_uri` that comes with neither a hint nor a `client_id`.

### Revocation

| Provider           | Refresh token revoked: its access tokens?                                                                                                                           | Access token revoked: what else?                                                                                                                                                                                                       | Public Clients                                                                                                                           | Another Client's token                                                                                                                                        | Source                                                                                                                           |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| node-oidc-provider | Yes: every access token, refresh token and code of the grant, and the grant itself.                                                                                 | Every token of the grant, refresh tokens included; only the grant record is kept. JWT access tokens cannot be revoked: `unsupported_token_type`, "Structured JWT Tokens cannot be revoked" (`lib/shared/reject_structured_tokens.js`). | `client_id` alone (`none`).                                                                                                              | Confidential: `invalid_request`, "client is not authorized to revoke the presented token". Public: 200, nothing revoked, "to disallow guessing valid tokens". | `lib/actions/revocation.js`, `lib/helpers/revoke.js`, `lib/helpers/defaults.js` (`revocationAllowedPolicy`, `revokeGrantPolicy`) |
| Keycloak           | Yes: the client session is detached ("make sure that issued access-tokens are revoked as well"); an offline token also removes the Client from the offline session. | Only that token: its `jti` is kept in a revoked-token store until its `exp`.                                                                                                                                                           | `client_id` alone.                                                                                                                       | 400 `invalid_request`, "Unmatching clients". An unknown or invalid token gets `invalid_token` in the body with status 200.                                    | `protocol/oidc/endpoints/TokenRevocationEndpoint.java`, `protocol/oidc/refresh/DefaultRefreshTokenProvider.java`                 |
| Ory Hydra          | Yes: the refresh tokens and access tokens of the whole request ID.                                                                                                  | The same: the refresh tokens and access tokens of that request ID.                                                                                                                                                                     | `client_id` alone (`token_endpoint_auth_method: none`).                                                                                  | `unauthorized_client` internally, but any error other than `invalid_request` or `invalid_client` is written as 200; nothing is revoked.                       | `fosite/handler/oauth2/revocation.go`, `fosite/revoke_handler.go`                                                                |
| Spring AS          | Yes: the authorization's current access token, and an unused code.                                                                                                  | Only that access token.                                                                                                                                                                                                                | Not by default: the public-client converter matches only a code exchange with `code_verifier`, so a public Client gets `invalid_client`. | `invalid_client`.                                                                                                                                             | `authentication/OAuth2TokenRevocationAuthenticationProvider.java`, `web/authentication/PublicClientAuthenticationConverter.java` |

All four revoke a refresh token's access tokens with it. Revoking an access
token reaches the refresh tokens in node-oidc-provider and Hydra, and only
that token in Keycloak and Spring. 3 of 4 accept a public Client by its
`client_id`; Spring does not by default. On another Client's token they
differ: Keycloak and node-oidc-provider, for confidential Clients, answer
`invalid_request`; Hydra and node-oidc-provider, for public Clients, answer
200 and revoke nothing; Spring answers `invalid_client`. node-oidc-provider
answers a token it cannot find with an empty 200.

### CORS at revocation

| Provider           | What it does                                                                                                                                                                                                                                                                                                                                        | Source                                                                                             |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| node-oidc-provider | On by default, by the same `clientBasedCORS` policy as its token endpoint: the origin `null` is refused; otherwise an origin is allowed only for a Client registered for `none`, and only if it is the origin of one of that Client's redirect URIs; a confidential Client's origin gets `invalid_request`. Preflights are answered for any origin. | `lib/helpers/initialize_app.js`, `lib/helpers/defaults.js`                                         |
| Keycloak           | The origins of the Client's Web Origins, for any Client type; otherwise 403 "Invalid origin". Preflights allow POST and OPTIONS.                                                                                                                                                                                                                    | `protocol/oidc/endpoints/TokenRevocationEndpoint.java`, `protocol/oidc/utils/WebOriginsUtils.java` |
| Ory Hydra          | Only with `serve.public.cors.enabled`. Then an origin is allowed if it matches the global `allowed_origins`, or that list is empty, or it matches the authenticating Client's `allowed_cors_origins`. Preflights are always allowed.                                                                                                                | `x/oauth2cors/cors.go`, `oauth2/handler.go`                                                        |
| Spring AS          | No CORS code in the authorization server module; CORS is whatever the application configures in Spring Security. What its reference documentation recommends is **UNVERIFIED**.                                                                                                                                                                     | `oauth2/oauth2-authorization-server/src/main`                                                      |

node-oidc-provider's policy at revocation is the one pulsar already applies
at its token endpoint ([CORS for browser-based Clients](cors.md)).

### `resource` handling

| Provider           | Parameter                                                                             | Registered                                                                                                                                                                                                                                                                            | Validation                                                                           | How many                                                                                                                                                                                     | Without `resource`                                                                                                                                                                    | Source                                                                                    |
| ------------------ | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| node-oidc-provider | `resource`                                                                            | In code: the deployer must implement `getResourceServerInfo`, which by default throws `InvalidTarget`, and which returns the Resource Server's scopes and, optionally, its audience and token format. The documentation advises "Only allow client's pre-registered resource values." | Absolute URI, no fragment; otherwise `invalid_target`.                               | Several at authorization, "but only a single audience for an Access Token is permitted"; the token request picks one, or `defaultResource` must, or the request fails with `invalid_target`. | With `openid` in scope, "an Access Token for the UserInfo Endpoint is returned". Access tokens "shall always only contain scopes that are defined on the respective Resource Server". | `lib/helpers/defaults.js` (`features.resourceIndicators`), `lib/shared/check_resource.js` |
| Keycloak           | `resource`, behind the experimental feature `RESOURCE_INDICATORS`, off unless enabled | Not as separate objects: the `resource` must equal an audience the token would already carry, matched as `urn:client:<clientId>`, as a literal audience, or by a Client's `resource_url` attribute; otherwise `invalid_target`. The `aud` is then narrowed to that value.             | Absolute, no fragment and no query, or a URN.                                        | One. Both endpoints refuse a repeated parameter with `invalid_request`, except for token exchange. A refresh or a code exchange must use the original `resource`, or omit it.                | The audience Keycloak's mappers compute, not narrowed (which mappers apply by default is **UNVERIFIED**).                                                                             | `protocol/oidc/resourceindicators/`, `common/.../Profile.java`                            |
| Ory Hydra          | None; its own `audience` parameter, several values or one space-separated             | Per Client, `audience` in its metadata. By default a requested audience must match a registered one by scheme and host, with a path equal to or under it; otherwise `invalid_request`. The consent app grants audiences.                                                              | By the matching strategy; `ExactAudienceMatchingStrategy` exists for non-URI values. | Several.                                                                                                                                                                                     | `aud` is empty (**UNVERIFIED** in a running instance). Scopes and audiences are independent lists.                                                                                    | `fosite/audience_strategy.go`, `fosite/handler/oauth2/strategy_jwt.go`                    |

Several values of `resource` are uncommon. RFC 8707 §3 discourages them;
node-oidc-provider accepts several at authorization but issues tokens of one
audience; Keycloak accepts one; Hydra has no `resource`, and its `audience`
allows several. MCP's authorization specification (revision 2026-07-28)
requires clients to send `resource` in authorization and token requests
([OpenID Provider survey](oidc.md#mcp-authorization-spec-revision-2026-07-28));
that MCP clients never send two is **UNVERIFIED**.

Sources: <https://github.com/panva/node-oidc-provider/tree/3ed87bef95d0f02b72917b9eb7d17ef5c3b2313b>,
<https://github.com/keycloak/keycloak/tree/e649c7732498971ddc8254e9a9f2b65428aa8b17>,
<https://github.com/ory/hydra/tree/4174065ffb052799890f7480f5360a877a67ffc1>,
<https://github.com/spring-projects/spring-security/tree/fc7249dc7afba47d30dd1877d0634401b1fd98da/oauth2/oauth2-authorization-server>.

## What pulsar takes from this

Decided on 2026-11-09.

### Form Post

- Every response, errors included, uses form_post when it is requested. The
  response mode is determined before other parameters are validated. The
  Form Post plan reads errors from the POST body, and Core §3.1.2.6 sends
  errors by the requested Response Mode.
- The auto-submitting page works under the login package's CSP, by a nonce
  or a hash for its script, and a visible button submits it when scripts
  are off. `default-src 'none'` blocks an inline script but
  not the submission, and whether the suite's HtmlUnit enforces CSP is
  unknown.

### RP-Initiated Logout

- Discovery lists `end_session_endpoint` (§2.1). GET and POST are both
  supported (§2), though the suite sends only GET.
- The End-User is always asked to confirm before their Login Session ends.
  §2 makes this a SHOULD, and a MUST without a hint or with one that does
  not belong to the current session. The modules that expect no redirect
  allow a confirmation, the suite's automation can click through one, and
  node-oidc-provider always asks.
- `id_token_hint` is optional, as it is in §2. Its signature, issuer and
  audience are checked, which the two forged-hint modules exercise. Its
  `exp` is not checked, as Spring does not check it: this goes beyond §2's
  SHOULD, which asks only that a hint be accepted after its expiry when its
  RP has a current or recent session.
- The OP redirects only when the Client is identified, by the hint or by
  `client_id`, and the `post_logout_redirect_uri` exactly matches one
  registered for that Client (§3). The redirect echoes `state`, which the
  suite checks unchanged at 128 characters. Otherwise the OP shows a
  signed-out page, as §4 allows and the modules that expect no redirect
  accept.
- The registry's Clients gain `post_logout_redirect_uris` (§3.1); the suite
  needs `/post_logout_redirect` registered for its Clients.
- `logout_hint` and `ui_locales` are ignored, as §2 allows; the suite sends
  neither.

### Logout and tokens

- Logout revokes no Refresh Token Family. All four providers keep offline
  tokens through logout, and pulsar issues refresh tokens only for offline
  access.
- Logout deletes no access token. They expire within ten minutes, no
  specification surveyed requires it, and the providers split 2–2.
- OAuth 2.1 draft -17 §9.3.2's SHOULD, to tie a browser-based application's
  refresh token to the session, is not followed. It is a draft, no provider
  surveyed does it, and the departure is to be recorded beside its
  requirement.

### Revoking tokens

- Revoking a refresh token revokes its whole Refresh Token Family and the
  access tokens issued from it, as RFC 7009 §1 and §2.1 describe and all
  four providers do.
- Revoking an access token revokes only that token, as Keycloak and Spring
  do. It takes effect at UserInfo; a Resource Server that verifies the JWT
  itself accepts it until it expires, at most ten minutes later, the case
  RFC 7009 §3 and §5 describe.
- Public Clients authenticate with `client_id` alone (RFC 7009 §5), as 3 of
  4 providers allow.
- Another Client's token is refused with 400 `invalid_request`, since
  RFC 7009 §2.1 requires the request be refused and names no error code;
  Keycloak and node-oidc-provider use that code for confidential Clients.
- An invalid token gets 200 (RFC 7009 §2.2).
- CORS follows the token endpoint's policy, as node-oidc-provider's does;
  RFC 7009 §2.3 allows CORS, and OAuth 2.1 §3.2 requires it for
  browser-based applications.
- Discovery lists `revocation_endpoint`,
  `revocation_endpoint_auth_methods_supported` and, since `private_key_jwt`
  is among those methods, `revocation_endpoint_auth_signing_alg_values_supported`
  (RFC 8414 §2), which the Config OP plan's schema accepts.

### Resource Indicators

- The registry gains Resource Servers, each with an identifier, an absolute
  URI without a fragment (RFC 8707 §2), and the scopes it accepts, as
  node-oidc-provider's `getResourceServerInfo` returns them.
- Each Client lists the Resource Servers it may request, as
  node-oidc-provider's documentation advises and Hydra's Client `audience`
  does, and as RFC 9700 §4.10.2 allows of a server that knows every
  resource server.
- A request carries at most one `resource`, as RFC 8707 §3 encourages and
  Keycloak enforces. More than one, or an unregistered or unpermitted one,
  gets `invalid_target`.
- Without `resource`, the audience stays the issuer (REQ-AT-5), as RFC 8707
  §2.1 and RFC 9068 §3 allow.
- An access token for a Resource Server names it as `aud` and carries only
  its scopes, the audience restriction RFC 8707 §2 and RFC 9700 §2.3 ask
  for. A Refresh Token Family keeps its Resource Server, and a token request
  naming another one gets `invalid_target`.
- A Resource Server's scopes are its own, apart from OpenID Connect's,
  as node-oidc-provider keeps each resource's scopes apart.
