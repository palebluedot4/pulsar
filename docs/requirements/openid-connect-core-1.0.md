# OpenID Connect Core 1.0

Clauses of [OpenID Connect Core 1.0 incorporating errata set 2](https://openid.net/specs/openid-connect-core-1_0.html)
that pulsar, as an OP, must or should meet.

## ID Token (§2)

- REQ-CORE-1 (§2, `sub`): "Subject Identifier. A locally unique and never
  reassigned identifier within the Issuer for the End-User ... It MUST NOT
  exceed 255 ASCII [RFC20] characters in length. The sub value is a
  case-sensitive string."
- REQ-CORE-2 (§2, `aud`): "It MUST contain the OAuth 2.0 client_id of the
  Relying Party as an audience value."
- REQ-CORE-3 (§2, `nonce`): "If present in the Authentication Request,
  Authorization Servers MUST include a nonce Claim in the ID Token with the
  Claim Value being the nonce value sent in the Authentication Request."

- REQ-CORE-10 (§2, `iss`): "REQUIRED. Issuer Identifier for the Issuer of
  the response."
- REQ-CORE-11 (§2, `exp`): "REQUIRED. Expiration time on or after which the
  ID Token MUST NOT be accepted by the RP when performing authentication
  with the OP."
- REQ-CORE-12 (§2, `iat`): "REQUIRED. Time at which the JWT was issued."
- REQ-CORE-13 (§2, `auth_time`): "When a max_age request is made or when
  auth_time is requested as an Essential Claim, then this Claim is
  REQUIRED; otherwise, its inclusion is OPTIONAL."

  pulsar includes `auth_time` in every ID token.

## Authorization endpoint (§3.1.2)

- REQ-CORE-4 (§3.1.2.1): "Authorization Servers MUST support the use of the
  HTTP GET and POST methods defined in RFC 7231 [RFC7231] at the
  Authorization Endpoint."
- REQ-CORE-5 (§3.1.2.1, `redirect_uri`): "This URI MUST exactly match one of
  the Redirection URI values for the Client pre-registered at the OpenID
  Provider, with the matching performed as described in Section 6.2.1 of
  [RFC3986] (Simple String Comparison)."
- REQ-CORE-6 (§3.1.2.2): "Verify that a scope parameter is present and
  contains the openid scope value. (If no openid scope value is present,
  the request may still be a valid OAuth 2.0 request but is not an OpenID
  Connect request.)"

  pulsar serves only OpenID Connect requests, so it answers a request
  without `openid` with `invalid_scope`.

### `prompt`, `max_age` and hints (§3.1.2.1)

- REQ-CORE-14 (§3.1.2.1, `prompt=none`): "The Authorization Server MUST
  NOT display any authentication or consent user interface pages. An error
  is returned if an End-User is not already authenticated or the Client
  does not have pre-configured consent for the requested Claims or does not
  fulfill other conditions for processing the request."

  pulsar asks for nothing but a login and a Consent, so it answers
  `login_required` or `consent_required`, never `interaction_required`. A
  request a Client sends by POST from its own site arrives without the
  SameSite=Lax Login Session cookie; with or without `prompt=none`, it is
  first sent back to the authorization endpoint by GET, which carries the
  cookie, and is answered there.

- REQ-CORE-15 (§3.1.2.3): "The Authentication Request contains the prompt
  parameter with the value login. In this case, the Authorization Server
  MUST reauthenticate the End-User even if the End-User is already
  authenticated."

  Only a login on the login page for that request, in the last 10 minutes,
  counts; one made before it, or for another request, does not.

- REQ-CORE-16 (§3.1.2.1, `prompt=consent`): "The Authorization Server
  SHOULD prompt the End-User for consent before returning information to
  the Client."
- REQ-CORE-17 (§3.1.2.1, `prompt=select_account`): "The Authorization
  Server SHOULD prompt the End-User to select a user account."

  A Login Session holds one End-User, so pulsar has no other End-Users of a
  browser to offer; the login page is where a person chooses which End-User
  to be, by signing in. `select_account` sends the End-User there, as
  `login` does.

- REQ-CORE-18 (§3.1.2.1, `prompt`): "If this parameter contains none with
  any other value, an error is returned."

  The error is `invalid_request`.

- REQ-CORE-19 (§3.1.2.1, `prompt`): "If an OP receives a prompt value
  outside the set defined above that it does not understand, it MAY return
  an error or it MAY ignore it; in practice, not returning errors for
  not-understood values will help facilitate phasing in extensions using
  new prompt values."

  pulsar ignores such a value, as the clause advises, except that `none`
  with it is still an error (REQ-CORE-18).

- REQ-CORE-20 (§3.1.2.1, `max_age`): "If the elapsed time is greater than
  this value, the OP MUST attempt to actively re-authenticate the End-User.
  ... Note that max_age=0 is equivalent to prompt=login."

  The elapsed time is counted in whole seconds, as `auth_time` is, and from
  any login, including one made for the same request, until the End-User
  has also decided on the consent page for that request, after that login
  and in the last 10 minutes: the request was then re-authenticated, and
  measuring again would send an End-User slower than `max_age` back to log
  in, around and around. `max_age=0`, like `prompt=login`, is satisfied by
  a login on the login page for that request, made in the last 10
  minutes. A value that is not a non-negative
  integer is `invalid_request`; one too large for 64 bits sets no limit.

- REQ-CORE-21 (§3.1.2.1, `display`): "If an OP receives a display value
  outside the set defined above that it does not understand, it MAY return
  an error or it MAY ignore it"

  pulsar ignores `display` and serves every value the same page: plain HTML
  without script, with a viewport meta tag. This departs from the SHOULDs
  that ask for a popup, touch or feature-phone variant; the pages have no
  layout to vary, and #11 leaves presentation beyond them out of scope.

- REQ-CORE-22 (§3.1.2.1, `ui_locales`): "An error SHOULD NOT result if some
  or all of the requested locales are not supported by the OpenID
  Provider."

  The pages are in English only; #11 leaves localization out of scope.

- REQ-CORE-23 (§5.2, `claims_locales`): "An error SHOULD NOT result if some
  or all of the requested locales are not supported by the OpenID
  Provider."
- REQ-CORE-24 (§3.1.2.1, `id_token_hint`): "If the End-User identified by
  the ID Token is already logged in or is logged in as a result of the
  request (...), then the Authorization Server returns a positive response;
  otherwise, it MUST return an error, such as login_required."

  An End-User other than the one the hint names is sent to the login page
  once, unless `prompt=none`; if the login there is not the named
  End-User's either, the error is `login_required`. Its signature is not
  verified: whatever a hint names, a positive response is about the
  End-User signed in.

  A hint that is not a JWT naming pulsar as its issuer and an End-User as
  its subject identifies no End-User, and is answered with
  `invalid_request`, which RFC 6749 §4.1.2.1 defines for a request that
  "includes an invalid parameter value". This departs deliberately from
  #18, which asks that `id_token_hint` be accepted without error: a hint
  pulsar cannot read cannot be checked as this clause requires, and
  ignoring it would answer positively for an End-User the Client may not
  have meant.

- REQ-CORE-25 (§3.1.2.1, `login_hint`): "Hint to the Authorization Server
  about the login identifier the End-User might use to log in (if
  necessary)."

  pulsar fills the login form's username field with it.

- REQ-CORE-26 (§3.1.2.1, `acr_values`; §5.5.1): "The acr Claim is requested
  as a Voluntary Claim by this parameter." and "the Authorization Server
  MUST NOT generate an error when Claims are not returned, whether they are
  Essential or Voluntary, unless otherwise specified in the description of
  the specific claim."

  pulsar has one authentication level and never returns `acr` (#11).

### Authentication and consent (§3.1.2.3, §3.1.2.4)

- REQ-CORE-27 (§3.1.2.3): "When interacting with the End-User, the
  Authorization Server MUST employ appropriate measures against Cross-Site
  Request Forgery and Clickjacking as, described in Sections 10.12 and
  10.13 of OAuth 2.0 [RFC6749]."

  The login and consent forms refuse cross-origin submissions, and no page
  may be framed (REQ-BCP-2).

- REQ-CORE-28 (§3.1.2.4): "Once the End-User is authenticated, the
  Authorization Server MUST obtain an authorization decision before
  releasing information to the Relying Party."

  The decision is the End-User's, on the consent page, which names the
  Client by its `client_id` and lists the scopes it asks for. It is
  remembered as a Consent per End-User and Client, which a later request
  for no other scopes reuses.

### Error codes (§3.1.2.6)

- REQ-CORE-29 (§3.1.2.6, `login_required`): "The Authorization Server
  requires End-User authentication. This error MAY be returned when the
  prompt parameter value in the Authentication Request is none, but the
  Authentication Request cannot be completed without displaying a user
  interface for End-User authentication."
- REQ-CORE-30 (§3.1.2.6, `consent_required`): "The Authorization Server
  requires End-User consent. This error MAY be returned when the prompt
  parameter value in the Authentication Request is none, but the
  Authentication Request cannot be completed without displaying a user
  interface for End-User consent."

## ID Token for the Authorization Code Flow (§3.1.3.6)

- REQ-CORE-7 (§3.1.3.6, `at_hash`): "Its value is the base64url encoding of
  the left-most half of the hash of the octets of the ASCII representation
  of the access_token value, where the hash algorithm used is the hash
  algorithm used in the alg Header Parameter of the ID Token's JOSE
  Header."

  `at_hash` is OPTIONAL in this flow; pulsar always includes it.

## UserInfo (§5.3)

- REQ-CORE-36 (§5.3): "The UserInfo Endpoint MUST support the use of the
  HTTP GET and HTTP POST methods defined in RFC 7231 [RFC7231]."
- REQ-CORE-37 (§5.3): "The UserInfo Endpoint MUST accept Access Tokens as
  OAuth 2.0 Bearer Token Usage [RFC6750]."

  In the `Authorization` header, or, by POST, in the form-encoded body
  (REQ-BEARER-1, REQ-BEARER-2). The token is validated as RFC 9068 §4
  requires of a resource server (REQ-AT-6 to REQ-AT-11), and its record
  must be current: recorded, and not expired. A token whose code was
  redeemed twice has no record (REQ-OAUTH-29).

- REQ-CORE-38 (§5.3.2): "The sub (subject) Claim MUST always be returned
  in the UserInfo Response."
- REQ-CORE-39 (§5.3.2): "If a Claim is not returned, that Claim Name SHOULD
  be omitted from the JSON object representing the Claims; it SHOULD NOT
  be present with a null or empty string value."
- REQ-CORE-40 (§5.3.2): "The content-type of the HTTP response MUST be
  application/json if the response body is a text JSON object; the
  response body SHOULD be encoded using UTF-8."

  Go encodes JSON in UTF-8.

  Every response, success or error, also carries `Cache-Control: no-store`
  (#11), since it is about an End-User or a credential.

- REQ-CORE-41 (§5.3.3): "When an error condition occurs, the UserInfo
  Endpoint returns an Error Response as defined in Section 3 of OAuth 2.0
  Bearer Token Usage [RFC6750]."

§5.3 also says the UserInfo Endpoint "SHOULD support the use of
Cross-Origin Resource Sharing (CORS) [CORS] and/or other methods as
appropriate to enable JavaScript Clients and other Browser-Based Clients
to access it." pulsar departs from this: no endpoint but discovery sends
CORS headers, and a browser-based Client that cannot reach the token
endpoint has no access token to send to UserInfo. CORS at UserInfo alone
would serve no Client. Other providers do answer cross-origin requests there
([research](../research/userinfo-and-claims.md)); #41 decides whether
pulsar should, at the token endpoint and UserInfo together.

## Claims (§5.4, §5.5)

- REQ-CORE-49 (§5.4): "The Claims requested by the profile, email,
  address, and phone scope values are returned from the UserInfo Endpoint,
  as described in Section 5.3.2, when a response_type value is used that
  results in an Access Token being issued."

  `code` always issues an access token, so the claims of the scopes
  granted are returned from UserInfo and never in the ID token. They are
  those §5.4 lists for each scope, which together are every Standard Claim
  (§5.1) but `sub`.

- REQ-CORE-42 (§5.5): "The claims parameter value is represented in an
  OAuth 2.0 request as UTF-8 encoded JSON (which ends up being
  form-urlencoded when passed as an OAuth parameter)."

  A value that is not a JSON object, whose `userinfo` or `id_token` member
  is neither an object nor null, whose individual requests are neither
  objects nor null, or that gives a member twice, is answered with
  `invalid_request`, as is the parameter repeated.

- REQ-CORE-43 (§5.5, `userinfo`): "Requests that the listed individual
  Claims be returned from the UserInfo Endpoint. If present, the listed
  Claims are being requested to be added to any Claims that are being
  requested using scope values."
- REQ-CORE-44 (§5.5, `id_token`): "Requests that the listed individual
  Claims be returned in the ID Token. If present, the listed Claims are
  being requested to be added to the default Claims in the ID Token."
- REQ-CORE-45 (§5.5, §5.5.1): "Any members used that are not understood
  MUST be ignored."

  So is a requested claim pulsar cannot release: one that is not a
  Standard Claim, or carries a language tag (§5.5.2). `essential` makes no
  difference, since "the Authorization Server MUST NOT generate an error
  when Claims are not returned, whether they are Essential or Voluntary,
  unless otherwise specified in the description of the specific claim"
  (§5.5.1). Of the claims pulsar can release, only `sub` is so specified
  (REQ-CORE-48).

- REQ-CORE-46 (§5.5.1, `value` and `values`): "When the Claim value does
  not match the requested value, the Claim is not included in the
  response." and "When the Claim value does not match any of the requested
  values, the Claim is not included in the response."

  Values are compared as decoded JSON values. A claim that a scope granted
  also requests is returned whatever its value: the claims parameter adds
  to what the scopes request (REQ-CORE-43).

- REQ-CORE-47 (§5.5.1): "Note that when the claims request parameter is
  supported, the scope values that request Claims, as defined in Section
  5.4, are effectively shorthand methods for requesting sets of individual
  Claims."

  A claim requested individually is released only with the End-User's
  Consent to the scope that requests it (REQ-CORE-28). The consent page
  asks for that scope, and allowing it remembers it, so the page may ask
  for more than the request releases, never less. node-oidc-provider keeps
  Consent per claim instead; Keycloak releases such a claim without Consent
  to its scope ([research](../research/userinfo-and-claims.md)).

- REQ-CORE-48 (§3.1.2.2): "If the sub (subject) Claim is requested with a
  specific value for the ID Token, the Authorization Server MUST only send
  a positive response if the End-User identified by that sub value has an
  active session with the Authorization Server or has been Authenticated
  as a result of the request."

  It is handled as `id_token_hint` is (REQ-CORE-24), and `values` as a set
  of such values. A value that is not a string, an empty `values`, or
  values of which none is the End-User an `id_token_hint` names, are
  answered with `invalid_request`.

## Request objects (§6)

- REQ-CORE-8 (§6.1): "Should an OP not support this parameter and an RP
  uses it, the OP MUST return the request_not_supported error."
- REQ-CORE-9 (§6.2): "Should an OP not support this parameter and an RP
  uses it, the OP MUST return the request_uri_not_supported error."

## Client authentication (§9)

pulsar offers `client_secret_basic`, `client_secret_post` and
`private_key_jwt`; `client_secret_jwt` is not offered. The clauses below
are those of `private_key_jwt`.

- REQ-CORE-31 (§9, `iss` and `sub`): "This MUST contain the client_id of
  the OAuth Client."
- REQ-CORE-32 (§9, `aud`): "The Authorization Server MUST verify that it is
  an intended audience for the token. The Audience SHOULD be the URL of
  the Authorization Server's Token Endpoint."

  pulsar accepts its token endpoint URL or its issuer (REQ-JWTAUTH-3).

- REQ-CORE-33 (§9, `jti`): "These tokens MUST only be used once, unless
  conditions for reuse were negotiated between the parties [...]"

  None are negotiated. A `jti` is kept per Client until its assertion's
  `exp`, after which the assertion is refused for its `exp` alone.

- REQ-CORE-34 (§9, `exp`): "Expiration time on or after which the JWT MUST
  NOT be accepted for processing."
- REQ-CORE-35 (§9): "The value of the [OAuth.Assertions]
  client_assertion_type parameter MUST be
  "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", per
  [OAuth.JWT]."

## Signing keys (§10.1)

- REQ-CORE-50 (§10.1): "The private key used to sign the content MUST be
  associated with a public key used for signature verification published
  by the sender in its JWK Set document. If there are multiple keys in the
  referenced JWK Set document, a kid value MUST be provided in the JOSE
  Header."

  A rotated key signs only once every replica that reloads on time, and
  every JWK Set a Client cached, publishes it (ADR 0003).

- REQ-CORE-51 (§10.1.1): "The JWK Set document at the jwks_uri SHOULD
  retain recently decommissioned signing keys for a reasonable period of
  time to facilitate a smooth transition."

  pulsar reads "a reasonable period" as until every token the key signed
  has expired: one reload interval plus the token lifetime after the next
  key's time to sign (ADR 0003).
