# UserInfo and the claims parameter: what other providers do

Surveyed 2026-11-06, after #21, to check four of its decisions against other
providers. Open-source providers were read from their source at these
release tags: node-oidc-provider v9.13.3, Keycloak 26.8.2, Ory Hydra v26.2.0
(module `ory/hydra/v2`, with fosite vendored), and Spring Authorization
Server 1.5.8. Paths are relative to each repository at its tag; line numbers
are approximate. Hosted providers were read from their documentation and
discovery documents, and their CORS behavior was observed by sending
unauthenticated requests from an unregistered origin. The OpenID conformance
suite was read at `release-v5.3.4`, under
`src/main/java/net/openid/conformance/`. Anything not confirmed is marked
**UNVERIFIED**.

## Consent to a claim requested through the claims parameter

pulsar asks for Consent to the scope that requests the claim, and remembers
that scope (REQ-CORE-47).

| Provider           | Behavior                                                                                                                                                                                                                                                  | Source                                                                                                                                |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| node-oidc-provider | Off by default. When enabled, Consent is kept per claim. The consent prompt's `op_claims_missing` check fires for a claim the grant does not hold; `sub`, `sid`, `auth_time`, `acr`, `amr` and `iss` are exempt. Allowing it calls `grant.addOIDCClaims`. | `lib/helpers/defaults.js`, `lib/helpers/interaction_policy/prompts/consent.js`, `lib/actions/interaction.js`                          |
| Keycloak           | Discovery says `true`. The parameter is honored only through an opt-in "Claims parameter Token" mapper, and only for `essential: true` on five claims. Consent is per client scope and never reads the parameter.                                         | `OIDCWellKnownProvider.java`, `mappers/ClaimsParameterTokenMapper.java`, `services/managers/AuthenticationManager.java`               |
| Ory Hydra          | Not supported; discovery reports `false`. Consent is per scope.                                                                                                                                                                                           | `oauth2/handler.go`, `flow/consent_types.go`                                                                                          |
| Spring AS          | Not supported. Consent is per scope, and `openid` alone needs none.                                                                                                                                                                                       | `OAuth2AuthorizationCodeRequestAuthenticationProvider.java`                                                                           |
| Auth0, Okta        | Discovery omits `claims_parameter_supported`, so it is `false`. Per-claim Consent is not documented (**UNVERIFIED**).                                                                                                                                     | `https://samples.auth0.com/.well-known/openid-configuration`, `https://okta.okta.com/oauth2/default/.well-known/openid-configuration` |
| Google             | Discovery omits the member; the documentation accepts `claims` for `amr` and `auth_time` only.                                                                                                                                                            | <https://developers.google.com/identity/openid-connect/openid-connect>                                                                |
| Microsoft Entra ID | Discovery omits the member; `claims` is documented for claims challenges and client capabilities on access tokens, not for End-User claims.                                                                                                               | <https://learn.microsoft.com/en-us/entra/identity-platform/claims-challenge>                                                          |

Only node-oidc-provider supports the parameter for End-User claims and keeps
Consent per claim. Keycloak releases a claim named in the parameter without
Consent to its scope. pulsar's choice asks for more than it releases, never
less; per-claim Consent, as node-oidc-provider keeps it, would need Consent
stored per claim rather than per scope (#11).

## The sub Claim requested with a value

pulsar handles it as it handles `id_token_hint` (REQ-CORE-48).

| Provider           | Behavior                                                                                                                                                               | Source                                            |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| node-oidc-provider | A login check, `claims_id_token_sub_value`, follows the `id_token_hint` check and has its shape: a mismatch asks for a login, and `prompt=none` gets `login_required`. | `lib/helpers/interaction_policy/prompts/login.js` |
| Keycloak           | No check found (**UNVERIFIED**: established by searching `protocol/oidc` and finding none).                                                                            | —                                                 |
| Ory Hydra          | The parameter is not parsed; `id_token_hint` alone is enforced, with `login_required` on a mismatch.                                                                   | `consent/strategy_default.go`                     |
| Spring AS          | The parameter is not parsed.                                                                                                                                           | —                                                 |
| Conformance suite  | No OIDCC module requests a `sub` value.                                                                                                                                | —                                                 |

pulsar matches node-oidc-provider. It differs only when `id_token_hint` and
the `sub` value name different End-Users: pulsar answers `invalid_request`,
where node-oidc-provider's two checks would, by their structure, end in
`login_required` (**UNVERIFIED**).

## CORS at UserInfo and the token endpoint

pulsar sends none, a departure from OpenID Connect Core 1.0 §5.3 recorded in
its requirements; #41 asks whether it should.

| Provider           | Behavior                                                                                                                                                                                                                                                                                          | Source                                                                                              |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| node-oidc-provider | Per Client, at UserInfo and the token endpoint. The default `clientBasedCORS` allows the origin of one of the Client's redirect URIs, and at the token endpoint only for a Client registered for `none`; it logs a warning advising that it be replaced. A refused origin gets `invalid_request`. | `lib/helpers/defaults.js`, `lib/shared/cors.js`, `lib/helpers/initialize_app.js`                    |
| Keycloak           | Per Client, by its Web Origins (`+` means its redirect URIs), at UserInfo and the token endpoint; a mismatch gets 403. Errors before the Client is known carry `*`.                                                                                                                               | `endpoints/UserInfoEndpoint.java`, `services/cors/DefaultCors.java`, `endpoints/TokenEndpoint.java` |
| Ory Hydra          | Off by default. When on, a global allow-list or the Client's `allowed_cors_origins`; on with an empty global list, every origin is allowed.                                                                                                                                                       | `oryx/configx/cors.schema.json`, `x/oauth2cors/cors.go`                                             |
| Spring AS          | None of its own; the application configures Spring Security's `cors()`.                                                                                                                                                                                                                           | `docs/modules/ROOT/pages/guides/how-to-pkce.adoc`                                                   |
| Auth0              | Observed: `Access-Control-Allow-Origin: *` at UserInfo and on the token endpoint's preflight. The documentation ties Allowed Origins to embedded login only.                                                                                                                                      | <https://auth0.com/docs/get-started/applications/set-up-cors>                                       |
| Okta               | Observed: any origin reflected at UserInfo and on the token endpoint's preflight. The documentation says OAuth 2.0 token requests need no Trusted Origin.                                                                                                                                         | <https://developer.okta.com/docs/guides/enable-cors/main/>                                          |
| Google             | Observed: any origin reflected at both. Not documented.                                                                                                                                                                                                                                           | —                                                                                                   |
| Microsoft Entra ID | Observed: `*` at Graph's `/oidc/userinfo`. Cross-origin redemption works only for a redirect URI of type `spa`.                                                                                                                                                                                   | <https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow>                |
| Conformance suite  | No condition checks `Access-Control-*` headers.                                                                                                                                                                                                                                                   | —                                                                                                   |

Every provider surveyed can answer cross-origin requests at UserInfo:
Ory Hydra and Spring AS once configured, the others by default. The hosted
ones allow any origin, relying on the bearer token; the open-source ones
restrict by Client, most often to the origins of its redirect URIs. Whether
a hosted provider gates a successful token response by Client was not
observed (**UNVERIFIED**). This bears on #41's second and third questions.

## Revoking tokens when a code is redeemed twice

RFC 6749 §4.1.2: the authorization server "SHOULD revoke (when possible) all
tokens previously issued based on that authorization code". pulsar leaves
this to #22.

| Provider            | Behavior                                                                                                                                                                                                             | Source                                                                                                                                                                                                             |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| node-oidc-provider  | Revokes everything under the code's grant ID (access tokens, refresh tokens, codes, and the Grant if its policy allows), then `invalid_grant`.                                                                       | `lib/helpers/grant_source.js`, `lib/helpers/revoke.js`, `lib/actions/grants/authorization_code.js`                                                                                                                 |
| Keycloak            | Detaches the client session from the user session, persisted past the error's rollback, then `invalid_grant`. That this invalidates its tokens is inferred, not traced (**UNVERIFIED**).                             | `utils/OAuth2CodeParser.java`, `grants/AuthorizationCodeGrantType.java`                                                                                                                                            |
| Ory Hydra (fosite)  | Revokes the access and refresh tokens of the code's request ID, then `invalid_grant`.                                                                                                                                | `fosite/handler/oauth2/flow_authorize_code_token.go`, `persistence/sql/persister_oauth2.go`                                                                                                                        |
| Spring AS           | Invalidates the refresh token, which cascades to the access token, or the access token if there is none; then `invalid_grant`.                                                                                       | `OAuth2AuthorizationCodeAuthenticationProvider.java`, `OAuth2Authorization.java`                                                                                                                                   |
| Auth0, Okta, Google | Reuse is refused; revocation is not documented (**UNVERIFIED**).                                                                                                                                                     | <https://support.auth0.com/center/s/article/auth0-oauth-2-0-authorization-code-expiry-time-and-one-time-use-controls>, <https://support.okta.com/help/s/article/invalid-grant-error-when-accessing-token-endpoint> |
| Microsoft Entra ID  | Reuse is refused with AADSTS54005, whose text suggests using an existing refresh token, which implies earlier tokens stay valid (an inference).                                                                      | <https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes>                                                                                                                                  |
| Conformance suite   | `oidcc-codereuse` and `oidcc-codereuse-30seconds` (both in the Basic OP plan): a second redemption not refused with 400 and `invalid_grant` is a FAILURE; a first access token still accepted after it is a WARNING. | `openid/AbstractOIDCCAuthCodeReuse.java`, `openid/OIDCCAuthCodeReuseAfter30Seconds.java`, `openid/OIDCCBasicTestPlan.java`                                                                                         |

Every open-source provider revokes, by keying the tokens a code issues to one
identifier taken from the code. pulsar's `access_tokens.code_hash` is such a
key. The hosted providers document refusal only.

## Also observed

The conformance suite's `oidcc-claims-essential` (Basic OP) requests
`{"userinfo": {"name": {"essential": true}}}`; `name` missing from UserInfo,
or present in the ID token, is a WARNING (`openid/OIDCCClaimsEssential.java`).
The Config OP plan checks `claims_parameter_supported` at INFO level only
(`openid/OIDCCDiscoveryEndpointVerification.java`).
