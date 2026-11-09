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
authorization, to revoke them together. A seventh was added the same day,
for #53: what other providers do with a code, a refresh token or an access
token whose End-User has since been removed from the user store, and
whether adding the End-User back restores them.

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

When surveyed, pulsar kept a redeemed code while the Refresh Token Family
it started had neither ended nor been revoked. Each authorization request
decided this for every expired code, with a `NOT EXISTS` join to the
families (`DeleteExpiredAuthorizationCodes`, then marked `TODO(#53)`); each
token response deleted expired access tokens. Ended families had an index
on `expiry`, "For deleting the families that have ended", but no query yet
deleted a family or its refresh tokens. #53 then took option A below, and
#59 moved every deletion out of requests into a periodic task.

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

## An End-User removed after a grant

None of the specifications read says what becomes of a code, a refresh
token or an access token whose End-User is removed while it is
outstanding. The nearest clauses:

- RFC 6749 §6 asks the authorization server to "validate the refresh
  token". OAuth 2.1 draft -17 §4.3.1 adds that it MUST "validate that the
  grant corresponding to this refresh token is still active", without
  saying what ends a grant.
- RFC 9700 §4.14.2 and OAuth 2.1 §4.3.3: authorization servers "MAY revoke
  refresh tokens automatically in case of a security event", with password
  change and logout at the authorization server as the examples. OAuth 2.1
  §9.3.2 asks that a browser-based application's refresh token be linked
  "to the user's authenticated session with the authorization server, so
  that when the user logs out, previously issued refresh tokens become
  invalid."
- OAuth 2.1 §7.9: authorization servers "SHOULD allow administrators and
  resource owners to view the set of clients that have been granted access
  to their resources and to revoke those grants".
- OpenID Connect Core §1.2 and §5.7: the Subject Identifier is "locally
  unique and never reassigned within the Issuer" for the End-User. An End-User
  added back with the same `sub` can only be the same End-User; whether their
  earlier grants come back with them is not said.

| Provider           | A code issued before removal, redeemed after                                                                                                                                                                                                                                                                                                            | A refresh token, after removal                                                                                                                                                                                                                   | An access token, after removal                                                                                                                 | What removal does, and an End-User added back                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Source                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Spring AS          | Tokens are issued. The authorization record holds the principal authenticated at authorization, and the tokens are built from it; no class in the authorization server's main source refers to `UserDetailsService`. A deployer's `OAuth2TokenCustomizer` could look the user up.                                                                       | Tokens are issued, from the stored principal; no user is reloaded.                                                                                                                                                                               | UserInfo answers with the claims of the ID token stored in the record. Introspection answers `active: true` from the record.                   | Nothing: the authorization server is not told. `OAuth2AuthorizationService` has `save`, `remove`, `findById` and `findByToken`, and no lookup by principal. Nothing stopped working, so adding the user back changes nothing.                                                                                                                                                                                                                                                                                                                                                  | `authentication/OAuth2AuthorizationCodeAuthenticationProvider.java`, `authentication/OAuth2RefreshTokenAuthenticationProvider.java`, `oidc/authentication/OidcUserInfoAuthenticationProvider.java` (`DefaultOidcUserInfoMapper`), `authentication/OAuth2TokenIntrospectionAuthenticationProvider.java`, `OAuth2AuthorizationService.java`                                                                                                                                                                                                                                                                                                                                                                                                     |
| fosite and Hydra   | Tokens are issued. Hydra has no user store, and its token endpoint asks the login and consent app nothing. A deployer may set `oauth2.token_hook`, unset by default, which Hydra calls on every token request before the code or refresh token is consumed; a 403 from it refuses the request with `access_denied`.                                     | Tokens are issued, from the session stored at consent. The same hook, or `oauth2.refresh_token_hook`, may refuse.                                                                                                                                | UserInfo answers with the ID token claims stored in the token's session. Introspection reads the token's row.                                  | Nothing, unless the deployer calls `DELETE /admin/oauth2/auth/sessions/consent` with the subject and `all=true`. That deletes the subject's access token and refresh token rows and its handled consent flows; on PostgreSQL, code rows that name a deleted flow are deleted with it (`ON DELETE CASCADE`). What it deletes does not come back when the End-User is added again; without it, nothing stopped working.                                                                                                                                                          | `hydra/oauth2/handler.go` (`oauth2TokenExchange`, `getOidcUserInfo`), `hydra/oauth2/token_hook.go`, `hydra/oauth2/refresh_hook.go`, `hydra/driver/config/provider.go` (`getHookConfig`), `hydra/consent/handler.go`, `hydra/persistence/sql/persister_consent.go` (`revokeConsentSession`), `hydra/persistence/sql/migrations/20211019000001000002_merge_authentication_request_tables.postgres.up.sql`, `fosite/handler/oauth2/flow_authorize_code_token.go`, `fosite/handler/oauth2/flow_refresh.go`                                                                                                                                                                                                                                        |
| node-oidc-provider | `invalid_grant`, "authorization code invalid (referenced account not found)", when the deployer's `findAccount` returns `undefined`; the default `findAccount`, a placeholder, returns an account for any `sub`. The code is consumed before the account is looked up, so a second attempt within its lifetime finds it consumed and revokes the grant. | `invalid_grant`, "refresh token invalid (referenced account not found)". The account is looked up before the reuse check and before rotation, so nothing is consumed or revoked, and a used refresh token for a removed account revokes nothing. | UserInfo refuses with `invalid_token`, "associated account not found". Introspection does not look the account up, and answers `active: true`. | Nothing: accounts are the deployer's, looked up at each use. Added back, the account's refresh tokens and access tokens work again, until they or the grant expire; the code does not, since it was consumed.                                                                                                                                                                                                                                                                                                                                                                  | `lib/actions/grants/authorization_code.js`, `lib/actions/grants/refresh_token.js`, `lib/helpers/grant_common.js` (`validateAccount`), `lib/helpers/grant_source.js`, `lib/helpers/configuration_result.js`, `lib/shared/access_token.js` (`loadAccessTokenAccount`), `lib/actions/userinfo.js`, `lib/actions/introspection.js`, `lib/helpers/defaults.js` (`findAccount`)                                                                                                                                                                                                                                                                                                                                                                     |
| Keycloak           | `invalid_grant`, "Code not valid": the code names its user session, which no longer exists, and there is no client session left to detach.                                                                                                                                                                                                              | `invalid_grant`: "Session not active" for a refresh token, "Offline user session not found" for an offline token.                                                                                                                                | UserInfo refuses with `invalid_token`, and introspection answers `active: false`: both look up the token's user session first.                 | Deleting a user publishes `UserRemovedEvent`, on which the session provider deletes the user's online and offline user sessions and their client sessions, in the database and the cache; the user's consents are deleted with the user. A user that a federation provider no longer validates is deleted the same way, by default (`removeInvalidUsersEnabled`). A user added back has none of the deleted sessions. `JpaUserProvider.addUser(realm, username)` generates a new ID, which is the user's `sub`; that the admin API's create goes through it is **UNVERIFIED**. | `models/UserManager.java`, `models/sessions/infinispan/InfinispanUserSessionProviderFactory.java`, `models/sessions/infinispan/PersistentUserSessionProvider.java`, `models/sessions/infinispan/InfinispanUserSessionProvider.java`, `models/jpa/session/JpaUserSessionPersisterProvider.java` (`onUserRemoved`), `models/jpa/JpaUserProvider.java`, `storage/UserStorageManager.java` (`deleteFederatedUser`), `storage/UserStorageProviderModel.java`, `protocol/oidc/utils/OAuth2CodeParser.java`, `protocol/oidc/grants/AuthorizationCodeGrantType.java`, `protocol/oidc/TokenManager.java`, `protocol/oidc/endpoints/UserInfoEndpoint.java`, `protocol/oidc/AccessTokenIntrospectionProvider.java`, `services/util/UserSessionUtil.java` |

The four split evenly on codes, refresh tokens and UserInfo. For a code and for a refresh
token presented after the End-User's removal, 2 of 4 refuse with
`invalid_grant`: node-oidc-provider, which looks the account up at each
use, and Keycloak, which deleted the user's sessions when the user was
deleted. Spring and Hydra issue tokens, since neither consults a user
store at the token endpoint; Hydra can be made to refuse by a token hook,
or to delete the tokens by its revocation API. UserInfo splits the same
way, 2 and 2. Introspection answers `active: true` in 3 of 4; Keycloak
alone answers `false`. 3 of 4 do nothing of their own when a user is
removed: Spring and Hydra are not told, and node-oidc-provider checks at
each use instead. Keycloak alone deletes, at removal, the sessions that
every code and refresh token of the user depends on. So of the two that
refuse, node-oidc-provider alone gives an End-User added back their
refresh tokens and access tokens again; in Spring and Hydra they never
stopped working.

### What pulsar takes from this: removal

pulsar's registry is a file read at start (ADR 0001), so it learns of a
removal only when it next looks an End-User up, and nothing can run when
the removal happens. Today a refresh token whose End-User is not in the
registry gets `invalid_grant`, checked after the reuse check, so a used one
still revokes its family; node-oidc-provider checks before it. UserInfo
answers `invalid_token` for an access token whose End-User is not in the
registry. Nothing is revoked, so an End-User added back has their unexpired
refresh tokens and access tokens again. A code issued before the removal is
still redeemed within its 60 seconds: the ID token carries `sub` and none of
the End-User's other claims, the refresh token issued with it is refused at
its first use, and UserInfo refuses the access token.

- (a) Option A: keep redeeming such a code, as Spring and Hydra do. Option
  B: refuse it with `invalid_grant`, as node-oidc-provider and Keycloak do,
  checking the registry as a refresh does, and rolling back so that the
  refusal consumes nothing. The four split 2 and 2, so no majority decides
  it; B makes the code agree with what pulsar already does for refresh
  tokens and UserInfo, and with node-oidc-provider, the one provider that
  also checks at use.
- (c) pulsar's UserInfo already refuses, as node-oidc-provider and Keycloak
  do. The option of answering from claims stored at issuance, as Spring and
  Hydra do, does not fit pulsar, which stores which claims were requested,
  not their values. pulsar has no introspection endpoint (#47).
- (d) Option A: keep revoking nothing, so that an End-User added back has
  their unexpired Refresh Token Families and access tokens again. Option B:
  at start, revoke the families and access tokens of every Subject not in
  the registry, the nearest pulsar can come to Keycloak's deletion at
  removal. It reads every family at each start, and replicas sharing
  PostgreSQL (ADR 0004) can run with different files during a rollout, so
  one could revoke for an End-User the others still accept. Option C:
  revoke a family when its refresh is refused for a missing End-User, which
  none of the four does.
- The majority practice points to A on (d): 3 of 4 do nothing when a user is
  removed, and node-oidc-provider, the one of those that refuses at use,
  gives the tokens back when the account returns. Since a `sub` is never
  reassigned (OpenID Connect Core §5.7) and ADR 0001 writes it in the file,
  an End-User added back with the same Subject is the same End-User.
