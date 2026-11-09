# OpenID Connect RP-Initiated Logout 1.0

Clauses of [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
that pulsar, as an OP, must or should meet. The `end_session_endpoint`
metadata of §2.1 is REQ-DISC-23. pulsar registers no Client for Session
Management, Front-Channel or Back-Channel Logout, so §2's notification of
other RPs has no one to notify, and `sid` is neither issued nor read.

## The logout request (§2)

- REQ-LOGOUT-1 (§2): "OpenID Providers MUST support the use of the HTTP
  GET and POST methods defined in [...] at the Logout Endpoint."

  A POST a Client sends from its own site arrives without the SameSite=Lax
  Login Session cookie, so its confirmation page names no End-User, and is
  answered for whoever is signed in then. The confirmation form carries the
  request in its body, so no URL pulsar sends the browser to holds the
  hint, whichever method the Client used.

- REQ-LOGOUT-2 (§2, `id_token_hint`): "When an id_token_hint parameter is
  present, the OP MUST validate that it was the issuer of the ID Token."

  pulsar accepts as a hint only a JWT signed by RS256, the algorithm of
  its ID tokens, with a key its JWK Set publishes; whose `typ` is that of
  its ID tokens, so that no access token stands in for one; whose `iss` is
  the issuer; and whose one audience is a registered Client. A hint that
  fails gets an error page, with no logout and no redirect.

- REQ-LOGOUT-3 (§2, `id_token_hint`): "The OP SHOULD accept ID Tokens when
  the RP identified by the ID Token's aud claim and/or sid claim has a
  current session or had a recent session at the OP, even when the exp
  time has passed."

  pulsar never checks a hint's `exp`, whatever the session, as Spring
  Authorization Server does not
  ([research](../research/logout-revocation-resources.md#rp-initiated-logout)).

  Limit: a hint must still verify against a key the JWK Set publishes
  (REQ-LOGOUT-2), and a key outlives its replacement's activation by
  eleven minutes only, the token lifetime plus a reload interval, while a
  Login Session lasts up to ten hours. So after `pulsar keys rotate`, an
  ID token the old key signed is refused as a hint, with the error page,
  even while the RP's session lasts. The RP can still log the End-User
  out by sending `client_id` instead of the hint.

- REQ-LOGOUT-4 (§2, `client_id`): "When both client_id and id_token_hint
  are present, the OP MUST verify that the Client Identifier matches the
  one used when issuing the ID Token."

  A `client_id` that does not match fails validation and is not used
  (REQ-LOGOUT-12): the request then identifies no Client, so it redirects
  nowhere, and the End-User is asked to confirm and shown that they are
  signed out. A `client_id` without a hint identifies the Client it names,
  if one is registered.

- REQ-LOGOUT-5 (§2, `post_logout_redirect_uri`): "The value MUST have been
  previously registered with the OP, either using the
  post_logout_redirect_uris Registration parameter or via another
  mechanism."

  The other mechanism is the registry (REQ-LOGOUT-10).

- REQ-LOGOUT-6 (§2, `state`): "If included in the logout request, the OP
  passes this value back to the RP using the state parameter when
  redirecting the User Agent back to the RP."

  The redirect adds `state`, unchanged, and no other parameter.

- REQ-LOGOUT-7 (§2, `ui_locales`): "An error SHOULD NOT result if some or
  all of the requested locales are not supported by the OpenID Provider."

  pulsar ignores `ui_locales`, and `logout_hint`, of which §2 says: "The
  value and meaning of this parameter is left up to the OP's discretion."

- REQ-LOGOUT-8 (§2): "At the Logout Endpoint, the OP SHOULD ask the
  End-User whether to log out of the OP as well. Furthermore, the OP MUST
  ask the End-User this question if an id_token_hint was not provided or
  if the supplied ID Token does not belong to the current OP session with
  the RP and/or currently logged in End-User. If the End-User says "yes",
  then the OP MUST log out the End-User."

  pulsar asks in every case, naming the Client when the request identifies
  it. Saying yes deletes the Login Session and clears its cookie. Saying
  no keeps it, and returns the End-User to the Client as a logout would,
  or shows that they are still signed in, or signed out if no Login
  Session is left.

## Redirection and registration (§3)

- REQ-LOGOUT-9 (§3): If `id_token_hint` "is not supplied with
  post_logout_redirect_uri, the OP MUST NOT perform post-logout
  redirection unless the OP has other means of confirming the legitimacy
  of the post-logout redirection target. The OP also MUST NOT perform
  post-logout redirection if the post_logout_redirect_uri value supplied
  does not exactly match one of the previously registered
  post_logout_redirect_uris values."

  The other means is a `client_id` whose Client registered the URI. With
  neither a hint nor a `client_id`, pulsar never redirects. The URI is
  compared with those of the identified Client as a string, so a query
  added, a trailing slash or a host in another case does not match.

- REQ-LOGOUT-10 (§3.1, `post_logout_redirect_uris`): "OPTIONAL. Array of
  URLs supplied by the RP to which it MAY request that the End-User's User
  Agent be redirected using the post_logout_redirect_uri parameter after a
  logout has been performed."

  The registry checks each as it does a redirect URI (REQ-OAUTH-1): an
  absolute URI without a fragment. Each is listed once per Client.

## Validation and errors (§4)

- REQ-LOGOUT-11 (§4): "it is explicitly not an error for an RP to request
  that a logout be performed when the OP does not consider that the
  End-User is logged in with the OP at the requesting RP."

  A browser without a Login Session is asked to confirm, and then
  returned to the Client or shown that it is signed out, as one with a
  Login Session is. So is one whose Login Session ends while the page is
  open: the logout is done, and its answer is not asked for again.

- REQ-LOGOUT-12 (§4): "If any of the validation procedures defined in
  this specification fail, any operations requiring the information that
  failed to correctly validate MUST be aborted and the information that
  failed to validate MUST NOT be used." And: "when the OP detects errors in
  the RP-Initiated Logout request, the OP MUST not perform post-logout
  redirection to an RP."

  A hint that fails gets an error page. A parameter pulsar reads that is
  repeated does too, as no clause says which value would count.

## Security (§6)

- REQ-LOGOUT-13 (§6): "Logout requests without a valid id_token_hint value
  are a potential means of denial of service; therefore, OPs should obtain
  explicit confirmation from the End-User before acting upon them."

  The confirmation form refuses cross-origin submissions, as the consent
  form does. A page shown for an End-User, or for no one, ends no other
  End-User's Login Session: if another is signed in when it is answered,
  they are asked instead. A page shown for a Client's cross-site POST,
  which carries no cookie, names no one, and ends the Login Session of
  whoever is signed in when it is answered.
