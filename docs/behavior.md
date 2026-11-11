# Behavior

What pulsar does at each endpoint, for reference. Each normative statement
it implements has an ID in [requirements/](requirements/), cited by the
tests that prove it; the reasons for choices the specifications leave open
are in the [ADRs](adr/). Terms such as Client, End-User, Login Session and
Refresh Token Family are defined in [GLOSSARY.md](../GLOSSARY.md).

## Lifetimes

| What                                 | Lifetime                                                    | Where it is set                 |
| ------------------------------------ | ----------------------------------------------------------- | ------------------------------- |
| Authorization code                   | 60 seconds                                                  | `internal/oidc/provider.go`     |
| ID token and access token            | 10 minutes                                                  | `internal/oidc/provider.go`     |
| Refresh Token Family                 | 30 days from the redemption of the code that started it     | `internal/oidc/provider.go`     |
| Login Session                        | 30 minutes idle, 10 hours at most                           | `internal/login/login.go`       |
| Client assertion                     | `exp` at most an hour ahead; one minute of leeway on `nbf`  | `internal/oidc/assertion.go`    |
| Count of failed logins               | Forgotten a day after the last attempt                      | `internal/guessing/guessing.go` |
| Signing keys: reload by each replica | Every minute                                                | `internal/signing/signing.go`   |
| JWK Set cache (`Cache-Control`)      | 1 minute                                                    | `internal/signing/signing.go`   |
| Discovery cache (`Cache-Control`)    | 1 hour                                                      | `internal/oidc/discovery.go`    |
| Expired records deleted              | Every 15 minutes, by each replica (see [Cleanup](#cleanup)) | `cmd/pulsar/main.go`            |

Key rotation has its own schedule, in
[operations.md](operations.md#rotating-the-signing-key).

## Discovery and the JWK Set

- The discovery document is at `/.well-known/openid-configuration` under
  the issuer. It answers any origin.
- The JWK Set answers any origin. It holds the public keys pulsar signs
  with, which are RS256 keys.
- Until the migrations are applied and the signing keys loaded, the JWK
  Set answers 503, as do every protocol endpoint and page but their
  cross-origin preflights. Discovery answers from the start.

## Authorization endpoint

pulsar supports the authorization code flow alone, by GET or POST.

**Redirect URIs.** A redirect URI must equal one the Client registered,
character for character. There is one exception: a public Client's
loopback IP redirect URI, such as `http://127.0.0.1/callback`, may name any
port, as RFC 8252 §7.3 requires for native apps. A `localhost` URI gets no
such exception.

**PKCE.** A public Client must use PKCE with `S256`; a confidential Client
may ([ADR 0002](adr/0002-pkce-required-for-public-clients-only.md)). A
`code_challenge` without a method means `plain`, and is refused.

**Request parameters.**

- `prompt` acts on `none`, `login`, `consent` and `select_account`, and
  ignores other values; `none` combined with another value is refused with
  `invalid_request`.
- `max_age` asks the End-User to log in again once it has passed.
- `id_token_hint`, and a `sub` requested in the `claims` parameter, limit
  which End-User the response may be about.
- The `claims` parameter requests individual claims in the ID token or
  from UserInfo.
- Request objects are not supported: `request` gets
  `request_not_supported`, and `request_uri` gets
  `request_uri_not_supported`.

**Response modes.** By default the code or error is in the redirect URI's
query. A Client may send `response_mode=form_post` once, with an `http` or
`https` redirect URI. Every response pulsar then sends to that URI, the
code or an error, arrives in the body of a POST. The POST comes from a page
that submits itself by a script its Content-Security-Policy allows by hash,
with a button for a browser without script. A repeated `response_mode`, or
`form_post` with a redirect URI of another scheme, is refused with
`invalid_request` in the query.

**Issuer.** Every authorization response, an error included, carries
`iss`, as RFC 9207 defines.

**Login and consent.** An End-User without a Login Session is sent to the
login page, at `/login` under the issuer, and the request resumes after
login. Logins are throttled per End-User: after five failed attempts, each
attempt waits, from one second, doubling, to fifteen minutes at most
([ADR 0005](adr/0005-logins-throttled-per-end-user-by-delay.md)). The
consent page remembers the scopes an End-User allows each confidential
Client. A public Client cannot prove its identity, so the consent page asks
for it every time.

**Resource indicators.** A Client may ask, with one `resource` parameter
(RFC 8707), for an access token for a Resource Server the registry lets it
request. It must ask for at least one of that Resource Server's scopes
beside OpenID Connect's. The consent page lists them, with their
descriptions, under the Resource Server's identifier. A `resource` that is
not permitted, unregistered, malformed or repeated, or one without any of
its scopes, gets `invalid_target`, as does one at the token endpoint other
than the one authorized.

## Token endpoint

**Client authentication.** A confidential Client authenticates with
`client_secret_basic`, `client_secret_post` or `private_key_jwt`; a public
Client sends only its `client_id`.

- A `private_key_jwt` assertion must name pulsar's issuer as its sole
  audience, as RFC 10070 requires, so one naming the token endpoint is
  refused ([ADR 0006](adr/0006-client-assertions-name-the-issuer-as-sole-audience.md)).
  It may be signed with RS256, PS256 or ES256, and each assertion is
  accepted once.
- Client secrets are not throttled, since anyone could hold up a Client
  whose failed attempts were counted.
- Each replica runs at most as many Argon2id verifications at once, for
  logins and Client secrets together, as fill `GOMAXPROCS` times the
  memory of the largest hash in the registry. A token request that waits
  two seconds without room gets 503 with `temporarily_unavailable` and
  `Retry-After`.
- A Client gets `unauthorized_client` for a grant the registry does not
  list for it.

**Authorization code grant.** The token response carries an ID token and
an access token. Each code is redeemed once. A second redemption of a code,
by its own Client, with its redirect URI, and with a matching
`code_verifier` exactly when the code has a challenge, revokes the access
tokens issued from it. It also revokes the Refresh Token Family the code
started, for as long as that family lives. This holds after the code has
expired too, while its record is kept.

**Refresh tokens.** A request with `offline_access` and `prompt=consent`
asks the End-User for offline access. If they allow it, the token response
carries a refresh token.

- The Client redeems it with the `refresh_token` grant for a new access
  token, ID token and refresh token, for a narrower scope if it asks, for
  up to thirty days.
- Each refresh token is redeemed once. One already redeemed, presented
  again by its own Client while its Refresh Token Family lives, revokes the
  whole family, with no grace period. Its refresh tokens are refused from
  then on, and UserInfo refuses its access tokens.
- A refresh keeps the Resource Server the first token was for. A
  `resource` other than that one gets `invalid_target`.

**Client credentials grant.** A machine Client, a confidential Client
registered for the client credentials grant alone, gets an access token of
its own, with no End-User (RFC 6749 §4.4).

- It names one Resource Server it may request with `resource`, and asks in
  `scope` for scopes of that Resource Server it is registered for.
- Neither has a default. A request without `resource` gets
  `invalid_target`; one without `scope`, or for a scope the Client is not
  registered for, gets `invalid_scope`. A scope the Client is registered
  for, but of another Resource Server than `resource` names, gets
  `invalid_target`.
- The response carries no refresh token and no ID token.
- The access token's `sub` and `client_id` are the Client's `client_id`
  ([ADR 0007](adr/0007-a-machine-clients-sub-is-its-client-id.md)).

**Access tokens.** Access tokens are JWTs in the profile of RFC 9068, with
`typ` `at+jwt`, signed RS256, and valid for ten minutes.

- Without `resource`, the access token is for UserInfo: its `aud` is the
  issuer.
- With `resource`, its `aud` is the Resource Server's identifier and its
  `scope` holds only that Resource Server's scopes, so UserInfo refuses
  it. The ID token is unchanged.

## UserInfo

- UserInfo returns the End-User's `sub` and the claims of the `profile`,
  `email`, `address` and `phone` scopes granted, and those the `claims`
  parameter requested.
- It answers GET and POST, with the access token in the `Authorization`
  header or the body.
- It accepts only access tokens for UserInfo.

## Revocation endpoint

A Client may revoke a refresh token or access token issued to it at the
revocation endpoint (RFC 7009), authenticating as at the token endpoint.

- A refresh token revokes its whole Refresh Token Family and the access
  tokens issued in it.
- An access token for UserInfo revokes only itself, and UserInfo refuses
  it from then on.
- An access token for a Resource Server is answered 200 and nothing is
  revoked, as RFC 7009 §3 allows for a self-contained token.
- A Resource Server that verifies a JWT itself accepts it until it
  expires, at most ten minutes later, whether or not it was revoked.

## Logout

A Client may send the End-User to the logout endpoint, the
`end_session_endpoint` of discovery, at `/logout` under the issuer, by GET
or POST (OpenID Connect RP-Initiated Logout 1.0).

- pulsar asks the End-User to confirm every time, naming the Client when an
  `id_token_hint` or a `client_id` identifies it. Confirming ends the Login
  Session; declining keeps it.
- pulsar then returns the End-User to the `post_logout_redirect_uri`, with
  `state` and nothing else, only if the identified Client registered
  exactly that URI. Otherwise it shows a page that says whether they are
  signed out.
- An `id_token_hint` must be an ID token pulsar issued to a registered
  Client, and a `client_id` sent with it must name that Client. A hint
  refused, or a `client_id` that does not match it, gets an error page and
  logs no one out.
- The hint may have expired, and may be signed by a key that
  `pulsar keys rotate` replaced. That key leaves the JWK Set eleven minutes
  after the new key starts signing. pulsar still accepts hints it signed,
  and nothing else it signed, until ten hours and a minute after the new
  key started signing: the longest a Login Session in which the old key
  signed can last from then, plus a reload interval's margin.
- The request is carried in the confirmation form's body, so no URL pulsar
  sends the browser to holds the hint.
- Logout revokes no refresh token and no access token.

## Cross-origin requests

- A public Client running in a browser on another origin may call the
  token endpoint, the revocation endpoint and UserInfo from the origin of
  one of its redirect URIs.
- UserInfo also answers a confidential Client from the origins of its own
  redirect URIs.
- A confidential Client may not call the token and revocation endpoints
  from a browser, since a browser cannot keep its secret. RFC 10017
  recommends a backend-for-frontend, a confidential Client on the server,
  over a Client that runs in the browser.
- A request from a browser on an origin the Client may not use is refused
  with 400 and `invalid_request`.
- Discovery and the JWK Set answer any origin. The authorization endpoint
  answers none.

## Registry changes

pulsar reads the registry at startup
([configuration.md](configuration.md#the-registry)).

- While an End-User is out of the registry, no code or refresh token issued
  for them is redeemed, and UserInfo refuses their access tokens.
- A Client out of the registry cannot authenticate, so it redeems neither.
  UserInfo still accepts its access tokens until they expire, but not from
  a browser on another origin.
- Removal revokes nothing, so an End-User or Client added back has the
  tokens not yet expired again.

## Cleanup

Every 15 minutes, each replica deletes:

- the codes no longer kept for a second redemption to revoke;
- the expired access tokens, client assertions and Login Sessions;
- the ended Refresh Token Families, with their refresh tokens;
- the counts of login attempts, a day after the last.
