# Refresh tokens: what the conformance suite checks and what other providers do

Surveyed 2026-11-06 for #47, the refresh token specification. It covers two
questions: what the conformance suite's `oidcc-refresh-token` module needs
from pulsar to pass rather than skip, and how long other providers keep
recognizing a reused authorization code once refresh tokens exist, and what
they revoke when they do.

The OpenID conformance suite was read at `release-v5.3.4`, with paths under
`src/main/java/net/openid/conformance/`. Open-source providers were read from
their source at these tags:

- Spring Authorization Server 1.5.8; the same logic is in Spring Security
  7.1.2
- ORY fosite v0.49.0 and Ory Hydra v26.2.0
- node-oidc-provider v9.13.3
- Keycloak 26.8.2

Paths are relative to each repository at its tag. OAuth 2.1 was read as draft-ietf-oauth-v2-1-17 (October 2026),
which is still a draft. Anything not confirmed is marked **UNVERIFIED**.

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

## What pulsar takes from this

- Discovery lists `offline_access` and `refresh_token`. Each refresh returns
  a new refresh token and ID token, so that the suite checks both.
- A used code is kept, linked to the Refresh Token Family it started, until
  the family ends and the code itself has expired, as Spring and fosite keep
  theirs. So a reuse is recognized
  for as long as there is a family to revoke, and no longer.
- pulsar revokes only on a replay that would otherwise be valid: the same
  Client, the same redirect URI and a matching `code_verifier`. This follows
  OAuth 2.1 §7.5.3, as Spring and node-oidc-provider do. The keeping of the
  used code is what makes this possible, since checking a replay needs the
  code's Client, redirect URI and challenge. It changes what #22 decided,
  which revoked whichever Client presented the code. The change matters now
  that a family lasts thirty days: anyone who has seen a code could otherwise
  end an End-User's offline access with any Client.
- A replaced refresh token presented again revokes its family, with no grace
  period. The FAPI 2.0 test above expects the opposite, but pulsar does not
  implement FAPI 2.0.
