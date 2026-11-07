# Refresh tokens: what the conformance suite checks and what other providers do

Surveyed 2026-11-06 for #47, the refresh token specification. It covers two
questions: what the conformance suite's `oidcc-refresh-token` module needs
from pulsar to pass rather than skip, and how long other providers keep
recognizing a reused authorization code once refresh tokens exist, and
whether a replay with invalid parameters revokes anything. A third was added
the same day, in review of #51: what other providers do with a refresh whose
`scope` leaves out `openid`. Three more were added on 2026-11-07, for #52
and #53: what other providers do when a refresh token already used is
presented again; how they decide when used codes, used refresh tokens and
grants may be deleted; and how they find every token issued under one
authorization, to revoke them together.

The OpenID conformance suite was read at `release-v5.3.4`, with paths under
`src/main/java/net/openid/conformance/`. Open-source providers were read from
their source at these tags:

- Spring Authorization Server 1.5.8; the same logic is in Spring Security
  7.1.2
- ORY fosite v0.49.0 and Ory Hydra v26.2.0
- node-oidc-provider v9.13.3
- Keycloak 26.8.2

Paths are relative to each repository at its tag. OAuth 2.1 was read as
draft-ietf-oauth-v2-1-17 (October 2026), which is still a draft. Anything not
confirmed is marked **UNVERIFIED**.

## The suite's oidcc-refresh-token module

The module is in the Basic OP plan (`openid/OIDCCBasicTestPlan.java`). It is
not in the Config OP plan.

| Step                  | What it does                                                                                                                                                                                                                                                                                                                 | Source                                                                                                                                                                                       |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Asking for it         | Sends `scope=openid offline_access` only if discovery's `scopes_supported` lists `offline_access`, and then adds `prompt=consent`. Otherwise it sends `openid` alone.                                                                                                                                                        | `condition/client/SetScopeInClientConfigurationToOpenIdOfflineAccessIfServerSupportsOfflineAccess.java`, `…/AddPromptConsentToAuthorizationEndpointRequestIfScopeContainsOfflineAccess.java` |
| No refresh token      | The module is skipped, with a WARNING if `grant_types_supported` lists `refresh_token`.                                                                                                                                                                                                                                      | `openid/OIDCCRefreshToken.java`                                                                                                                                                              |
| Discovery             | Issuing a refresh token while `grant_types_supported` lacks `refresh_token` is a WARNING.                                                                                                                                                                                                                                    | `condition/client/EnsureServerConfigurationSupportsRefreshToken.java`                                                                                                                        |
| Refreshing            | One refresh per Client, one second after the code exchange. client sends `scope` set to its configured scope; client2 sends no `scope`.                                                                                                                                                                                      | `sequence/client/RefreshTokenRequestSteps.java`                                                                                                                                              |
| The refresh response  | 200, JSON, `Cache-Control: no-store`, `token_type` Bearer and an access token of enough entropy are each a FAILURE if missing. A missing `expires_in` is a WARNING. A new ID token and a new refresh token are optional. If a new refresh token is returned, it must be at least 16 bytes with more than 96 bits of entropy. | `sequence/client/RefreshTokenRequestSteps.java`, `condition/client/EnsureMinimumRefreshTokenLength.java`                                                                                     |
| The new ID token      | If one is returned: `iss`, `sub`, `aud` and `azp` must equal the original's, `iat` must differ, and `auth_time` must equal the original's (OpenID Connect Core §12.2). Its `nonce`, `exp` and signature are not checked.                                                                                                     | `condition/client/CompareIdTokenClaims.java`                                                                                                                                                 |
| UserInfo              | The new access token must get 200 at UserInfo.                                                                                                                                                                                                                                                                               | `openid/AbstractOIDCCServerTest.java`                                                                                                                                                        |
| Binding to the Client | client2's refresh token, sent with client's credentials, must get 400 and `invalid_grant`.                                                                                                                                                                                                                                   | `openid/OIDCCRefreshToken.java`, `sequence/client/RefreshTokenRequestExpectingErrorSteps.java`                                                                                               |
| Reuse                 | Not tested. The module never sends a refresh token a second time.                                                                                                                                                                                                                                                            | `openid/OIDCCRefreshToken.java`                                                                                                                                                              |

Adding `offline_access` to `scopes_supported` and `refresh_token` to
`grant_types_supported` changes no other Basic OP or Config OP module.

No plan in this release tests RFC 7009 revocation for an OP. The only
introspection test is Australia's CDR one, and the only rotation test is in
FAPI 2.0 (`fapi2spfinal/FAPI2SPFinalRefreshToken.java`). That test expects a
replaced refresh token to still work 30 seconds later. None of these can run
against pulsar, since FAPI 2.0 requires DPoP or mTLS and excludes client
secrets.

## A reused code, once refresh tokens exist

RFC 6749 §4.1.2 says the authorization server "SHOULD revoke (when possible)
all tokens previously issued based on that authorization code" and states no
period. RFC 9700 §4.2.4 adds none. OAuth 2.1 draft -17:

- §4.1.3 keeps the SHOULD, names "access tokens and refresh tokens", and
  triggers on "a second valid token request".
- §7.5.3: "The authorization server SHOULD NOT revoke any issued tokens when
  receiving a replayed authorization code that contains invalid parameters",
  such as a wrong `code_verifier` or client authentication. The reason it
  gives is denial of service.

| Provider           | How long a reuse is recognized                                                                                                                                                                                                                                                                                                   | Revocation on a replay with invalid parameters                                                                       | Source                                                                                                                                                                         |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Spring AS          | As long as the authorization record lives. The record holds the code, marked invalidated rather than removed, beside the tokens, and keeps it through refresh token rotation. A used code is recognized even after it expires. The framework never deletes a completed record; cleanup is left to the deployer.                  | No. Another Client's replay revokes nothing, and the redirect URI and PKCE are checked before the reuse branch.      | `OAuth2AuthorizationCodeAuthenticationProvider.java`, `OAuth2Authorization.java`, `OAuth2RefreshTokenAuthenticationProvider.java`                                              |
| fosite and Hydra   | As long as the used code's row lives. Hydra marks it inactive and dates it 30 minutes ahead "for reuse detection". Its janitor never deletes code rows, so in the open-source release they last longer; Ory's hosted service is **UNVERIFIED**. The tokens share the code's request ID, which every rotated refresh token keeps. | Yes. Revocation runs before the Client and PKCE checks.                                                              | `fosite/handler/oauth2/flow_authorize_code_token.go`, `fosite/handler/oauth2/flow_refresh.go`, `hydra/persistence/sql/persister_oauth2.go`, `hydra/cmd/cli/handler_janitor.go` |
| node-oidc-provider | Only while the code is unexpired, 60 seconds by default. Expiry is checked before use, so a later replay gets "expired" and revokes nothing.                                                                                                                                                                                     | No. The grant, PKCE and redirect URI are checked before the code is consumed, and revocation covers the whole grant. | `lib/actions/grants/authorization_code.js`, `lib/helpers/grant_source.js`, `lib/helpers/revoke.js`                                                                             |
| Keycloak           | As long as the session. The code string itself names the session and the Client, and no code state is kept after use. Any code not found, even an unused one that expired, detaches the Client from the session, and refresh then fails.                                                                                         | Yes. The detach runs before the redirect URI, Client and PKCE checks.                                                | `utils/OAuth2CodeParser.java`, `grants/AuthorizationCodeGrantType.java`, `TokenManager.java`                                                                                   |

The suite's `oidcc-codereuse-30seconds` replays a code with the same Client
30 seconds after its first use. A first access token still accepted after
that is a WARNING (`openid/OIDCCAuthCodeReuseAfter30Seconds.java`). Nothing
checks refresh tokens on code reuse, or a replay after the code's lifetime.

## A refresh whose scope leaves out openid

A Client may ask a refresh for a narrower scope (RFC 6749 §6), and so for
one without `openid`, such as `email` from a grant of
`openid email offline_access`. The specifications leave the answer open:

- OpenID Connect Core §3.1.2.1, `scope`: "OpenID Connect requests MUST
  contain the openid scope value. If the openid scope value is not present,
  the behavior is entirely unspecified."
- §12.2: the refresh response "is the Token Response of Section 3.1.3.3
  (Successful Token Response) except that it might not contain an
  id_token."
- RFC 6749 §6: the new refresh token's scope "MUST be identical to that of
  the refresh token included by the client in the request". OAuth 2.1
  draft -17 §4.3.3 keeps this, except where the grant itself has been
  reduced, as by the resource owner, not by a narrower `scope` in the
  request.

| Provider           | ID token on such a refresh                                         | New refresh token's scope | Access token at UserInfo                                   | Source                                                                                                                                                                                       |
| ------------------ | ------------------------------------------------------------------ | ------------------------- | ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Spring AS          | Issued: it checks the authorization's scopes for `openid`.         | The original              | Refused with `insufficient_scope`                          | `OAuth2RefreshTokenAuthenticationProvider.java` (`authorizedScopes.contains(OidcScopes.OPENID)`), `OidcUserInfoAuthenticationProvider.java`                                                  |
| node-oidc-provider | Not issued: it checks the scopes the request asked for.            | The original              | Refused: "access token missing openid scope"               | `lib/actions/grants/refresh_token.js`, `lib/helpers/grant_common.js` (`if (!scopes.has('openid')) return undefined`), `lib/actions/userinfo.js`                                              |
| fosite and Hydra   | Issued: the request's `scope` is replaced by the original's.       | The original              | Accepted, since the access token keeps the original scope  | `handler/oauth2/flow_refresh.go`, `handler/openid/flow_refresh_token.go` (`GetGrantedScopes().Has("openid")`)                                                                                |
| Keycloak           | Issued: it checks the original refresh token's scope for `openid`. | The original              | Accepted, since `openid` is added back to the access token | `protocol/oidc/refresh/AbstractRefreshTokenProvider.java` (`TokenUtil.isOIDCRequest(oldRefreshToken.getScope())`), `services/util/DefaultClientSessionContext.java`, `UserInfoEndpoint.java` |

None of the four refuses such a request. Three of four issue the ID token
from the original grant; node-oidc-provider alone issues it only when the
request itself asks for `openid`. Keycloak's default client scopes may be
added whatever the request says, which would make its narrowing remove
only optional scopes (**UNVERIFIED**). The conformance suite's refreshes
always include `openid`, so it checks neither behavior.

## What pulsar takes from this

- Discovery lists `offline_access` and `refresh_token`. Each refresh returns
  a new refresh token and ID token, so that the suite checks both.
- A used code is kept, linked to the Refresh Token Family it started, until
  the family ends and the code itself has expired. So a reuse is recognized
  for as long as there is a family to revoke, and no longer. Spring and
  fosite keep theirs at least as long; neither deletes a used code by
  itself.
- pulsar revokes only on a replay whose parameters are valid, as OAuth 2.1
  §7.5.3 asks and Spring and node-oidc-provider do: the request
  authenticates as the code's Client, by that Client's registered method,
  and carries the code's redirect URI and a `code_verifier` that matches its
  challenge. The code's own expiry is not one of these parameters: a valid
  replay after the code has expired still revokes, as long as the family
  lives. The keeping of the used code is what makes this possible, since
  checking a replay needs the code's Client, redirect URI and challenge. It changes what #22 decided,
  which revoked whichever Client presented the code. The change matters now
  that a family lasts thirty days: anyone who has seen a code could otherwise
  end an End-User's offline access with any Client.
- A replaced refresh token presented again revokes its family, with no grace
  period. The FAPI 2.0 test above expects the opposite, but pulsar does not
  implement FAPI 2.0.
- A refresh whose `scope` leaves out `openid` still returns an ID token,
  as Spring, fosite and Keycloak do, since the Refresh Token Family was
  granted for an OpenID authentication. The access token is for the scope
  the request asked for, and UserInfo accepts it, as fosite and Keycloak
  do; whether UserInfo should refuse an access token without `openid`, as
  Spring and node-oidc-provider do, is outside #51.

## A refresh token presented again

RFC 6749 §6 allows rotation: the authorization server "MAY issue a new
refresh token, in which case the client MUST discard the old refresh token
and replace it with the new refresh token. The authorization server MAY
revoke the old refresh token after issuing a new refresh token to the
client." On the refresh token's Client:

- RFC 6749 §6: the authorization server MUST "authenticate the client if
  client authentication is included and ensure that the refresh token was
  issued to the authenticated client". §10.4: "The authorization server
  MUST verify the binding between the refresh token and client identity
  whenever the client identity can be authenticated."
- RFC 9700 §4.14.2 requires sender-constrained refresh tokens or rotation
  "for public clients". Of rotation it says: "The previous refresh token is
  invalidated, but information about the relationship is retained by the
  authorization server." and "The authorization server cannot determine
  which party submitted the invalid refresh token, but it will revoke the
  active refresh token."
- OAuth 2.1 draft -17 §4.3.1 repeats this, and the server "will revoke the
  active refresh token as well as the access authorization grant associated
  with it". §4.3.3 names the cost: "a failure to deliver the refresh token
  response (e.g., due to a network error) can leave the client holding only
  an invalidated refresh token, forcing a new authorization flow." Draft -17
  has no refresh token subsection in §7; its refresh token rules are in
  §4.3.

None of these says whether a used refresh token presented by another,
authenticated Client should revoke anything. §7.5.3's "SHOULD NOT revoke
any issued tokens when receiving a replayed authorization code that
contains invalid parameters" is about codes.

| Provider           | Rotation by default                                                                                                                                                                                                         | Used token, its own Client                                                                                                                                                                                                                                                                         | Used token, another authenticated Client                                                               | Client authentication fails                                                        | Grace by default                                                                                                                                                                                         | Source                                                                                                                                                                                                                                                          |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Spring AS          | No. `reuseRefreshTokens` defaults to true, so a refresh returns the same refresh token until it expires (60 minutes by default). A Client set to false rotates.                                                             | Not detected. Rotation overwrites the refresh token in the authorization record, so the old one is not found: `invalid_grant`, and nothing is revoked.                                                                                                                                             | Not found either: `invalid_grant`, nothing revoked. For a current token, the Client check comes first. | The provider first requires an authenticated Client; nothing is revoked.           | None                                                                                                                                                                                                     | `settings/TokenSettings.java`, `authentication/OAuth2RefreshTokenAuthenticationProvider.java`, `JdbcOAuth2AuthorizationService.java` (`refresh_token_value = ?`)                                                                                                |
| fosite and Hydra   | Yes, for every Client. Hydra's strict rotation also marks every refresh token of the request used and deletes its access tokens on each refresh.                                                                            | `invalid_grant`. The presented token is deleted, then every refresh token and access token with its request ID.                                                                                                                                                                                    | The same revocation: the reuse branch runs before the Client check.                                    | Nothing: fosite returns the authentication error before calling the grant handler. | None: `rotation_grace_period` defaults to `0s`. It may be set to at most 5 minutes, or 180 days with `rotation_grace_reuse_count` (default 0). Within it, a used token refreshes as if it were not used. | `fosite/handler/oauth2/flow_refresh.go`, `fosite/access_request_handler.go`, `hydra/persistence/sql/persister_oauth2.go`, `hydra/driver/config/provider.go`, `hydra/spec/config.json`                                                                           |
| node-oidc-provider | Partly. The default `rotateRefreshToken` rotates a public Client's token that is not sender-constrained, and any token past 70% of its lifetime, but none once a year has passed since the first. `true` rotates every one. | `invalid_grant`. The token is destroyed and the grant revoked: every access token, refresh token and code with its `grantId`, of the kinds the Client may use, and by default the grant itself. Expiry is checked first, so an expired used token revokes nothing.                                 | Nothing: "client mismatch" is checked before the reuse branch.                                         | Nothing: client authentication runs before the grant handler.                      | None                                                                                                                                                                                                     | `lib/helpers/defaults.js` (`rotateRefreshToken`, `revokeGrantPolicy`), `lib/actions/grants/refresh_token.js`, `lib/helpers/revoke.js`, `lib/actions/token.js`                                                                                                   |
| Keycloak           | No. With "Revoke Refresh Token" off, the default for a new realm, a used refresh token stays valid until it or its session expires.                                                                                         | With it on: `invalid_grant`, and the Client's client session is detached from the user session. Every refresh token of that Client in that user session then fails, and so do its access tokens at UserInfo. This reaches beyond the one family. A token older than its family's latest fails too. | Nothing: `verifyRefreshToken` refuses a token issued for another Client before the reuse check.        | Nothing: the token endpoint authenticates the Client before the grant.             | None by time. "Refresh Token Max Reuse" is a count of extra uses, default 0.                                                                                                                             | `models/jpa/entities/RealmEntity.java`, `services/managers/RealmManager.java`, `protocol/oidc/refresh/AbstractRefreshTokenProvider.java`, `protocol/oidc/TokenManager.java`, `protocol/oidc/endpoints/TokenEndpoint.java`, `services/util/UserSessionUtil.java` |

Only fosite and Hydra rotate every Client's refresh token by default;
node-oidc-provider rotates public Clients' tokens, and Spring and Keycloak
rotate none unless configured. With rotation on, 3 of 4 detect a reuse by
the token's own Client and revoke its refresh tokens and access tokens;
Spring alone does not detect it, since it keeps no replaced refresh token.
Of those three, node-oidc-provider and Keycloak check the Client first and
revoke nothing for another Client; fosite alone revokes for any Client that
authenticates. All four revoke nothing when client authentication fails.
None has a grace period by default. Hydra can be given one of time, and
Keycloak one of a count.

### What pulsar takes from this: reuse

pulsar rotates every Client's refresh token. A used one presented again by
its own authenticated Client revokes its Refresh Token Family and deletes
the records of the access tokens issued from its code. One presented by
another Client gets `invalid_grant` and revokes nothing, since the Client
is checked first. A request whose client authentication fails is refused
before the refresh token is looked up. There is no grace period (#47).

- On each of these, pulsar does what the majority does: 2 of the 3
  providers that detect a reuse check the Client first, 4 of 4 revoke
  nothing when client authentication fails, and 4 of 4 have no grace
  period by default. The majority practice points to keeping it.
- Option: revoke on a reuse by any authenticated Client, as fosite alone
  does.
- Option: a grace period, which Hydra can be configured with. None of the
  four has one by default, and OAuth 2.1 §4.3.3 suggests sender-constrained
  refresh tokens rather than a grace period against lost responses.
- Rotating every Client's refresh token is the default of fosite and Hydra
  alone; RFC 9700 §4.14.2 requires rotation or sender-constraint only for
  public Clients. Here pulsar does not follow the majority default, though
  each of the four can be configured to rotate every Client's token.

## Keeping and deleting used codes, used refresh tokens and grants

RFC 6749 §10.4 says a previous refresh token "is invalidated but retained
by the authorization server", and RFC 9700 §4.14.2 that "information about
the relationship is retained by the authorization server". Neither says for
how long.

| Provider           | Used codes                                                                                            | Used refresh tokens                                                                                                                                                             | Grants                                                                                                                                                                                                               | How a record comes to be deleted                                                                                                                                                                                                                                                                                                                                                                                                      | Source                                                                                                                                                                                                                                                                                                                                           |
| ------------------ | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Spring AS          | Kept in the authorization record, marked invalidated.                                                 | Not kept: rotation overwrites the value in the record.                                                                                                                          | The authorization record, one `oauth2_authorization` row holding the code and the current tokens. A completed one is never deleted.                                                                                  | Never, by the framework. `remove` is called only for a pushed authorization request and for an authorization whose consent is denied, neither of them completed. The schema has the primary key alone; there is no expiry index. The in-memory service, for development only, keeps completed authorizations without limit.                                                                                                           | `JdbcOAuth2AuthorizationService.java`, `InMemoryOAuth2AuthorizationService.java`, `authentication/OAuth2AuthorizationConsentAuthenticationProvider.java`, `authentication/OAuth2AuthorizationCodeRequestAuthenticationProvider.java`, `oauth2-authorization-schema.sql`                                                                          |
| fosite and Hydra   | Marked inactive, with `expires_at` set 30 minutes ahead. Never deleted, as the earlier section found. | Marked inactive, with `expires_at` set 30 minutes ahead, plus any grace period. Deleted by the janitor, at the earliest a refresh token lifespan (720h by default) after issue. | The consent flow, `hydra_oauth2_flow`, whose ID is every token's request ID. The janitor deletes unhandled or rejected flows only, never a used one.                                                                 | A separate command, `hydra janitor`, run by the operator. With `--tokens` it deletes access and refresh token rows whose `requested_at` is older than the token lifespan, or than `--keep-if-younger` if that is older, in batches of `--batch-size` up to `--limit`, by indexes on `requested_at` and `nid`. `expires_at` is written but not read: the migration dropping its indexes notes "janitor still uses requested_at index". | `hydra/persistence/sql/persister_oauth2.go` (`flushInactiveTokens`, `newUsedExpiry`), `hydra/persistence/sql/persister_consent.go`, `hydra/cmd/cli/handler_janitor.go`, `hydra/persistence/sql/migrations/20230512112801000001_refresh_requested_at_index.up.sql`, `hydra/persistence/sql/migrations/20241012144910000001_unused_indices.up.sql` |
| node-oidc-provider | Marked consumed in place, and kept until the code's own expiry (60 seconds by default).               | Marked consumed in place, and kept until the token's own expiry (14 days by default).                                                                                           | A record with its own lifetime, `ttl.Grant` (14 days by default), set when it is saved. A refresh does not extend it, and one after it has expired gets "grant is expired". Tokens' lifetimes are independent of it. | Each record is written with `upsert(id, payload, expiresIn)`, its remaining lifetime in seconds, and the adapter, the deployer's store, deletes it then. Consuming a record keeps its lifetime. The provider runs no cleanup. The bundled memory adapter, an LRU of 1000 entries, gives each entry that age, and its index of a grant's tokens expires with the latest of them.                                                       | `lib/models/base_model.js`, `lib/models/base_token.js`, `lib/models/refresh_token.js`, `lib/helpers/defaults.js`, `lib/helpers/grant_source.js`, `lib/adapters/memory_adapter.js`, `example/my_adapter.js`                                                                                                                                       |
| Keycloak           | Stored in the single-use store with the realm's code lifespan when issued, and removed when used.     | No record: refresh tokens are signed tokens. The client session keeps, per family, the current token's ID, its use count, the latest token issued and when.                     | The user session and its client sessions, deleted when the session expires, with all the state above.                                                                                                                | A built-in scheduled task, `ClearExpiredUserSessions`, every 900 seconds by default (`scheduled.interval`). In the database store it selects sessions whose `lastSessionRefresh` or `createdOn` is older than the realm's idle or maximum lifespan allows, computed when it runs, using expiration indexes led by realm, offline flag and remember-me.                                                                                | `protocol/oidc/utils/OAuth2CodeParser.java`, `protocol/oidc/TokenManager.java`, `services/scheduled/ClearExpiredUserSessions.java`, `storage/datastore/DefaultDatastoreProviderFactory.java`, `models/jpa/session/PersistentUserSessionEntity.java`, `models/jpa/session/JpaUserSessionPersisterProvider.java`                                   |

3 of 4 decide when a record may be deleted from a time on the record
itself, with no join: node-oidc-provider writes each record's lifetime with
it, Hydra compares `requested_at` with the token lifespan, and Keycloak
compares a session's last refresh and creation with the realm's limits.
Spring alone deletes nothing it has completed; Hydra deletes no code and no
used consent flow either. None decides by a join to another table, and none
deletes on a request: Hydra and Keycloak run cleanup as a separate job,
node-oidc-provider leaves it to the store, and Spring to the deployer. Of
the three that keep used refresh tokens or their state, node-oidc-provider
and Hydra keep each used token's record until about when it would have
expired; Keycloak keeps only each family's latest, for as long as the
session.

### What pulsar takes from this: retention

pulsar keeps a redeemed code while the Refresh Token Family it started has
neither ended nor been revoked. Each authorization request decides this
for every expired code, with a `NOT EXISTS` join to the families
(`DeleteExpiredAuthorizationCodes`, marked `TODO(#53)`); each token response
deletes expired access tokens. Ended families have an index on `expiry`,
"For deleting the families that have ended", but no query yet deletes a
family or its refresh tokens.

- Option A: write on each code's row when it may be deleted, and move it as
  the code's state changes: when it is redeemed, to when its access tokens
  have expired; when it starts a family, to the family's end; when the
  family is revoked, back. Cleanup then compares that column, by an index,
  with no join. Ended families are deleted by their `expiry` the same way,
  their refresh tokens by the cascade. This is what 3 of 4 do.
- Option B: keep the join, but run it less often, as Hydra and Keycloak run
  cleanup apart from requests. Each run still checks every code kept for a
  family.
- Option C: delete a used code at its own expiry, as node-oidc-provider
  does, so that a valid replay after that revokes nothing. This reverses
  what the earlier section decided for #52.
- The majority practice points to A. When cleanup runs is a separate
  choice: none of the four deletes on a request, but under A each run
  reads only the rows that are due.

## Finding every token of one authorization

RFC 6749 §4.1.2 asks the server to revoke "all tokens previously issued
based on that authorization code". RFC 9700 §4.14.2 adds an implementation
note: "The grant to which a refresh token belongs may be encoded into the
refresh token itself. This can enable an authorization server to
efficiently determine the grant to which a refresh token belongs, and by
extension, all refresh tokens that need to be revoked." OAuth 2.1 draft -17
§4.3.1 keeps the note.

| Provider           | What the tokens of one authorization share                                                                                                                                                                                                                                           | What it covers                                                                                                                                                   | A separate per-family identifier                                                                                                                                                                                                                   | Source                                                                                                                                                                                                    |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Spring AS          | One authorization record. The code, the current access token, the current refresh token and the ID token are columns of its row, and revoking marks them invalidated there. An access token replaced by a refresh is no longer in the record; by default it is a self-contained JWT. | One authorization request.                                                                                                                                       | None: rotation replaces the refresh token in the same record.                                                                                                                                                                                      | `OAuth2Authorization.java`, `JdbcOAuth2AuthorizationService.java`, `settings/TokenSettings.java` (`accessTokenFormat`)                                                                                    |
| fosite and Hydra   | The request ID, stored on every code, access token, refresh token, OpenID Connect and PKCE row and kept by every refresh. Revocation deletes by `request_id`, which access and refresh token rows index. Hydra sets it to the consent request's ID.                                  | One authorization request.                                                                                                                                       | None. Each refresh token row also names the access token issued with it, `access_token_signature`, which graceful rotation uses to delete only that one.                                                                                           | `fosite/handler/oauth2/flow_refresh.go` (`request.SetID(originalRequest.GetID())`), `fosite/handler/oauth2/revocation_storage.go`, `hydra/persistence/sql/persister_oauth2.go`, `hydra/oauth2/handler.go` |
| node-oidc-provider | The `grantId`, on every code, access token and refresh token. Each model's adapter has `revokeByGrantId`.                                                                                                                                                                            | The grant, which by default a later authorization of the same Client in the same session reuses (`loadExistingGrant`), so one `grantId` may cover several codes. | None. A refresh token carries `rotations` and `iiat`, the first token's issue time, but no family identifier.                                                                                                                                      | `lib/helpers/revoke.js`, `lib/models/refresh_token.js`, `lib/helpers/defaults.js` (`loadExistingGrant`), `example/my_adapter.js`                                                                          |
| Keycloak           | The client session, one per Client per user session, which every token names through its session ID. Revocation detaches it.                                                                                                                                                         | Every authorization of that Client in that user session.                                                                                                         | Yes, with "Revoke Refresh Token" on: each code exchange gives its refresh token a new `reuse_id` claim, which every refresh carries on. Rotation state is kept per `reuse_id`, to detect a reuse; a reuse still detaches the whole client session. | `protocol/oidc/TokenManager.java` (`getReuseIdKey`, `generateRefreshToken`), `protocol/oidc/refresh/AbstractRefreshTokenProvider.java`, `models/Constants.java`                                           |

All four find the tokens to revoke by one identifier. For Spring and
fosite it covers one authorization; node-oidc-provider's grant and
Keycloak's client session can cover several. Keycloak alone keeps a
second, per-family identifier, and it uses it to detect a reuse, not to
revoke.

### What pulsar takes from this: linking

The hash of the code already reaches every token issued under it: an
access token's row holds it (`access_tokens.code_hash`), and so does the
Refresh Token Family's (`refresh_token_families.code_hash`), which its
refresh tokens reference. Revoking uses it. `access_tokens.family_id` is
written and indexed, but no query reads it.

- Option A: keep `code_hash` as the one identifier, and drop
  `access_tokens.family_id` and its index. It covers one authorization, as
  Spring's and fosite's identifiers do.
- Option B: write one row per redeemed code, with or without
  `offline_access`, whose ID every access token and refresh token carries,
  as Spring's record and node-oidc-provider's `grantId` do. It is one
  identifier too, at the cost of a new table; that row could also hold the
  deletion time of retention option A.
- Option C: keep both identifiers. None of the four keeps two to revoke.
- The majority practice points to one identifier, which A and B both are;
  A is the smaller change.
