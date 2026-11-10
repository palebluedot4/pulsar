# The client credentials grant

Surveyed 2026-11-10 for #88, the specification of the client credentials
grant, which would give a Client access tokens of its own, with no End-User. It
covers these questions: what RFC 6749, OAuth 2.1, RFC 9700, RFC 9068,
RFC 8707 and RFC 7591 require of the authorization server for this grant;
which Clients may use it, and how a Client is allowed to; which scopes and
which audience its access token gets, with and without `scope` and
`resource`; what its `sub` is, and how a Client's `sub` is kept from
colliding with an End-User's; whether it gets a refresh token or an ID
token; how pulsar's UserInfo and revocation endpoints treat such a token;
what discovery lists; whether the conformance suite tests it; and what
consumer in `examples/` would use it.

Open-source providers were read from their source at these commits:

- node-oidc-provider 9.13.3, `3ed87bef95d0f02b72917b9eb7d17ef5c3b2313b`
  (2026-11-04)
- Ory Hydra `master`, `4174065ffb052799890f7480f5360a877a67ffc1`
  (2026-07-29), which vendors fosite as `fosite/`
- Keycloak `main`, `e649c7732498971ddc8254e9a9f2b65428aa8b17` (2026-11-09,
  version 999.0.0-SNAPSHOT), with paths under
  `services/src/main/java/org/keycloak/` unless given in full
- Spring Authorization Server, in Spring Security `main` (7.2.0-SNAPSHOT),
  `fc7249dc7afba47d30dd1877d0634401b1fd98da` (2026-11-05), module
  `oauth2/oauth2-authorization-server`, with paths under
  `src/main/java/org/springframework/security/oauth2/server/authorization/`
- Zitadel `main`, `ae4364f473a4b4fd2217cf377492265fb31d92cc` (2026-11-09),
  and the library it pins in `go.mod`, `github.com/zitadel/oidc/v3`
  v3.47.5, cited as `oidc/v3:<path>`
- The OpenID conformance suite at `release-v5.3.4`, commit
  `23353b36957d6466010de767c812d2c91ed37638` (2026-10-26), with paths under
  `src/main/java/net/openid/conformance/`
- MCP's authorization extensions, `modelcontextprotocol/ext-auth` `main`,
  `15ca394e00a66434520b9ade26294999295a43ae` (2026-10-23)
- `golang.org/x/oauth2` v0.38.0, the version `examples/go.mod` requires

These are development heads, not releases, except x/oauth2 and the
conformance suite, and a released version may behave differently
(**UNVERIFIED** that each behaves the same). Paths are relative to each
repository at its commit. Auth0, Okta and Microsoft Entra ID were read from
their documentation on 2026-11-10, at the URLs given. OAuth 2.1 was read as
draft-ietf-oauth-v2-1-17 (2026-10-31), which is still a draft. Anything not
confirmed is marked **UNVERIFIED**.

## What the specifications require

### RFC 6749

| Clause | Topic                    | What it says                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ------ | ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| §1.3.4 | Use                      | Client credentials "can be used as an authorization grant when the authorization scope is limited to the protected resources under the control of the client, or to protected resources previously arranged with the authorization server. Client credentials are used as an authorization grant typically when the client is acting on its own behalf (the client is also the resource owner) or is requesting access to protected resources based on an authorization previously arranged with the authorization server."                                                                                                                                    |
| §2.1   | Client types             | Confidential: "Clients capable of maintaining the confidentiality of their credentials". Public: "Clients incapable of maintaining the confidentiality of their credentials".                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| §3.3   | Scope                    | "The authorization server MAY fully or partially ignore the scope requested by the client, based on the authorization server policy or the resource owner's instructions. If the issued access token scope is different from the one requested by the client, the authorization server MUST include the "scope" response parameter". And: "If the client omits the scope parameter when requesting authorization, the authorization server MUST either process the request using a pre-defined default value or fail the request indicating an invalid scope. The authorization server SHOULD document its scope requirements and default value (if defined)." |
| §4.4   | Client types             | "The client credentials grant type MUST only be used by confidential clients."                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| §4.4.1 | No authorization request | "Since the client authentication is used as the authorization grant, no additional authorization request is needed."                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| §4.4.2 | Request                  | `grant_type` "REQUIRED. Value MUST be set to "client_credentials"." `scope` "OPTIONAL. The scope of the access request as described by Section 3.3." "The client MUST authenticate with the authorization server as described in Section 3.2.1." "The authorization server MUST authenticate the client."                                                                                                                                                                                                                                                                                                                                                      |
| §4.4.3 | Response                 | "If the access token request is valid and authorized, the authorization server issues an access token as described in Section 5.1. A refresh token SHOULD NOT be included. If the request failed client authentication or is invalid, the authorization server returns an error response as described in Section 5.2."                                                                                                                                                                                                                                                                                                                                         |
| §5.2   | `unauthorized_client`    | "The authenticated client is not authorized to use this authorization grant type."                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| §5.2   | `invalid_scope`          | "The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the resource owner."                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| §5.2   | `unsupported_grant_type` | "The authorization grant type is not supported by the authorization server." pulsar answers `client_credentials` with it today.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

RFC 6749 names no way to record which Clients may use the grant or which
scopes they may get; §1.3.4 leaves it to "an authorization previously
arranged with the authorization server".

Source: <https://www.rfc-editor.org/rfc/rfc6749>.

### OAuth 2.1 draft -17

- §4.2 repeats RFC 6749 §4.4: "The client credentials grant type MUST only
  be used by confidential clients." The arrangement with another resource
  owner is "beyond the scope of this specification".
- §4.2.1: "The client credentials grant type is identified at the token
  endpoint with the grant_type value of client_credentials." The only
  parameter it adds is `scope`, "OPTIONAL". "The authorization server MUST
  authenticate the client."
- §4.2 has no response subsection, and the draft does not repeat RFC 6749
  §4.4.3's "A refresh token SHOULD NOT be included"; a search of the draft
  for that sentence finds nothing.
- §1.4.1 keeps RFC 6749 §3.3's rule for an omitted `scope`: "MUST either
  process the request using a predefined default value or fail the request
  indicating an invalid scope."
- §3.2.2 lists `client_credentials` among the three grant types the draft
  defines, and §3.2.4 keeps `unauthorized_client`: "The authenticated
  client is not authorized to use this authorization grant type."
- §7.4, "Client Impersonating Resource Owner", is RFC 9700 §4.15 below,
  reworded: "If the authorization server has a common namespace for client
  IDs and user identifiers, causing the resource server to be unable to
  distinguish an access token authorized by a resource owner from an access
  token authorized by a client itself, authorization servers SHOULD NOT
  allow clients to influence their client_id or any other claim if that
  can cause confusion with a genuine resource owner. Where this cannot be
  avoided, authorization servers MUST provide other means for the resource
  server to distinguish between the two types of access tokens."

Source: <https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-17.txt>.

### RFC 9700

- §2.3 asks that the privileges of an access token "SHOULD be restricted to
  the minimum required for the particular application or use case", and
  that access tokens "SHOULD be audience-restricted to a specific resource
  server" (REQ-BCP-14, REQ-BCP-15).
- §2.5: "Authorization servers SHOULD enforce client authentication if it
  is feasible". "It is RECOMMENDED to use asymmetric cryptography for
  client authentication, such as mutual TLS for OAuth 2.0 [RFC8705] or
  signed JWTs ("Private Key JWT") in accordance with [RFC7521] and
  [RFC7523]." With it, "authorization servers do not need to store
  sensitive symmetric keys, making these methods more robust against
  leakage of keys."
- §4.15, "Client Impersonating Resource Owner", is the only section that
  names the grant: "Resource servers may make access control decisions
  based on the identity of a resource owner for which an access token was
  issued, or based on the identity of a client in the client credentials
  grant." Quoting RFC 9068's `sub`, it goes on: "If both options are
  possible, a resource server may mistake a client's identity for the
  identity of a resource owner. For example, if a client is able to choose
  its own client_id during registration with the authorization server, a
  malicious client may set it to a value identifying a resource owner
  (e.g., a sub value if OpenID Connect is used)."
- §4.15.1: "Authorization servers SHOULD NOT allow clients to influence
  their client_id or any other claim that could cause confusion with a
  genuine resource owner if a common namespace for client IDs and user
  identifiers exists, such as in the sub claim example from [RFC9068]
  shown in Section 4.15 above. Where this cannot be avoided, authorization
  servers MUST provide other means for the resource server to distinguish
  between the two types of access tokens."

Source: <https://www.rfc-editor.org/rfc/rfc9700>.

### RFC 9068

- §2.2: "sub REQUIRED [...] In cases of access tokens obtained through
  grants where no resource owner is involved, such as the client
  credentials grant, the value of "sub" SHOULD correspond to an identifier
  the authorization server uses to indicate the client application. See
  Section 5 for more details on this scenario." "client_id REQUIRED - as
  defined in Section 4.3 of [RFC8693]."
- §3: "If the request does not include a "resource" parameter, the
  authorization server MUST use a default resource indicator in the "aud"
  claim. If a "scope" parameter is present in the request, the
  authorization server SHOULD use it to infer the value of the default
  resource indicator" (REQ-AT-5, REQ-AT-14).
- §5: "Authorization servers should prevent scenarios where clients can
  affect the value of the "sub" claim in ways that could confuse resource
  servers. For example, if the authorization server elects to use the
  client_id as the "sub" value for access tokens issued using the client
  credentials grant, the authorization server should prevent clients from
  registering an arbitrary client_id value, as this would allow malicious
  clients to select the sub of a high-privilege resource owner and confuse
  any authorization logic on the resource server relying on the "sub"
  value." It cites "Section 4.14 of [OAuth2.Security.BestPractices]", a
  draft whose section became §4.15 of RFC 9700.
- §6 is on privacy: "The client MUST NOT inspect the content of the access
  token", and "Administrators of authorization servers should also take
  into account that the content of an access token is visible to the
  client."

Source: <https://www.rfc-editor.org/rfc/rfc9068>.

### RFC 8707

- §2 defines `invalid_target` for "an authorization request or access
  token request": "The requested resource is invalid, missing, unknown, or
  malformed." It "can also be used to inform the client that it has
  requested an invalid combination of resource and scope."
- §2.1, for authorization requests, lets the server use "a predefined
  default resource value" when `resource` is omitted, or "require clients
  to specify the resource(s) they intend to access and [...] fail requests
  that omit the parameter with an "invalid_target" error."
- §2.2, for token requests: "When the "resource" parameter is used on an
  access token request made to the token endpoint, for all grant types, it
  indicates the target service or protected resource where the client
  intends to use the requested access token. The resource value(s) that is
  acceptable to an authorization server in fulfilling an access token
  request is at its sole discretion based on local policy or
  configuration."

So the server may refuse a token request without `resource`, with
`invalid_target`, or use a default; nothing in RFC 8707 says which for
this grant.

Source: <https://www.rfc-editor.org/rfc/rfc8707>.

### RFC 7591 metadata

pulsar has no Dynamic Client Registration (ADR 0001), but its registry
already names Client members as RFC 7591 §2 does: `client_id`,
`token_endpoint_auth_method`, `redirect_uris`, `jwks`. Two more fit this
grant:

- `grant_types`: "Array of OAuth 2.0 grant type strings that the client can
  use at the token endpoint", among them ""client_credentials": The client
  credentials grant type defined in OAuth 2.0, Section 4.4" and
  ""refresh_token": The refresh token grant type defined in OAuth 2.0,
  Section 6." "If omitted, the default behavior is that the client will use
  only the "authorization_code" Grant Type."
- `scope`: "String containing a space-separated list of scope values (as
  described in Section 3.3 of OAuth 2.0 [RFC6749]) that the client can use
  when requesting access tokens. The semantics of values in this list are
  service specific. If omitted, an authorization server MAY register a
  client with a default set of scopes."

And on registering the grant apart:

- `redirect_uris` are "for use in redirect-based flows such as the
  authorization code and implicit flows", and §2.1 pairs
  `client_credentials` with no response type.
- §5: "the "authorization_code" grant type is used to represent access on
  behalf of an end-user, but the "client_credentials" grant type represents
  access on behalf of the client itself. For security reasons, an
  authorization server could require that different scopes be used for
  these different use cases, and, as a consequence, it MAY disallow these
  two grant types from being registered together by the same client."

Source: <https://www.rfc-editor.org/rfc/rfc7591>.

### OpenID Connect and metadata

- OpenID Connect Core 1.0 §2: "The ID Token is a security token that
  contains Claims about the Authentication of an End-User by an
  Authorization Server when using a Client". With no End-User, there is
  nothing for an ID token to be about.
- Core §5.3: "The UserInfo Endpoint is an OAuth 2.0 Protected Resource that
  returns Claims about the authenticated End-User."
- Discovery 1.0 §3 and RFC 8414 §2: `grant_types_supported` is OPTIONAL,
  "a list of the OAuth 2.0 Grant Type values that this OP supports"; if
  omitted, the default is `["authorization_code", "implicit"]`. pulsar
  sends `["authorization_code", "refresh_token"]`.

Sources: <https://openid.net/specs/openid-connect-core-1_0.html>,
<https://openid.net/specs/openid-connect-discovery-1_0.html>,
<https://www.rfc-editor.org/rfc/rfc8414>.

### MCP's client credentials extension

The extension is "stable", revision 2026-07-28
(`specification/stable/oauth-client-credentials/2026-07-28/oauth-client-credentials.mdx`).
It requires "pre-registered client credentials, which are typically
established out-of-band through administrative channels. Dynamic Client
Registration is not used in this flow." Clients "MUST authenticate using
one of these methods": "JWT Authentication (RECOMMENDED)" per RFC 7523
§2.2, or "Client Secret". The authorization server's metadata "MUST"
include `token_endpoint_auth_methods_supported` with `private_key_jwt` or
`client_secret_basic`, and `token_endpoint_auth_signing_alg_values_supported`
"when supporting JWT authentication"; pulsar publishes both. Both of its
example token requests carry `resource` and `scope`. That MCP clients
always send `resource` with this grant follows from MCP's authorization
specification
([OpenID Provider survey](oidc.md#mcp-authorization-spec-revision-2026-07-28)),
not from the extension, which states no rule of its own on it.

Source: <https://github.com/modelcontextprotocol/ext-auth/tree/15ca394e00a66434520b9ade26294999295a43ae>.

## What pulsar does today

- The token endpoint answers `grant_type=client_credentials` with
  `unsupported_grant_type` (`exchange`, `internal/oidc/token.go`). Two
  tests assert it: "grant_type client_credentials" in
  `internal/server/authorization_test.go` and
  `internal/server/resource_test.go`.
- Every Client in the registry must list at least one redirect URI
  (`newClient`, `internal/registry/registry.go`), whatever its type.
  Clients have no `grant_types` or `scope` member, and the registry refuses
  a member it does not know.
- An End-User's Subject must be a UUID "in its lowercase hyphenated form"
  (`isUUID`); a `client_id` may be any non-empty string. No check keeps a
  `client_id` from equaling a Subject.
- A Resource Server's scopes are its own: none is one of OpenID Connect's
  (`openIDScopes`), and no two Resource Servers share one. So a scope value
  names at most one Resource Server.
- `signTokens` always signs an ID token beside the access token, and
  `tokenResponse.IDToken` is tagged `json:"id_token"` without `omitempty`.
- Each access token is recorded in `access_tokens`, whose `code_hash` is
  `NOT NULL` (migration `00004`), for UserInfo and revocation.
- UserInfo accepts only an access token whose `aud` holds the issuer
  (`validAccessTokenClaims`, REQ-AT-8), and then only for an End-User in
  the registry.
- The revocation endpoint looks an access token up by the same claims
  check, so a token whose `aud` is a Resource Server's is "not found" and
  answered with 200, revoking nothing. `TestRevokeAccessTokenClaims` in
  `internal/server/revocation_test.go` asserts it for "another aud".
- Access tokens live `TokenLifetime`, ten minutes
  (`internal/oidc/provider.go`).

## What providers do

### Allowing a Client, and public Clients

| Provider           | How a Client is allowed                                                                                                                                                                                           | Not allowed                                                                                                              | Public Client                                                                                                                                        | Source                                                                                                                                                                                            |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| node-oidc-provider | The server's `features.clientCredentials`, `{ enabled: false }` by default, and `client_credentials` in the Client's `grant_types`, whose default is `['authorization_code']`.                                    | `invalid_request`, "requested grant type is not allowed for this client"; `unsupported_grant_type` with the feature off. | Not refused: no check found in the grant, the token endpoint or the client schema (**UNVERIFIED** that a `none` Client with the grant gets a token). | `lib/helpers/defaults.js`, `lib/consts/client_attributes.js`, `lib/actions/token.js`                                                                                                              |
| Ory Hydra          | `client_credentials` in the Client's `grant_types`, whose default is `authorization_code` alone. The server always offers the grant.                                                                              | `unauthorized_client`, "The OAuth 2.0 Client is not allowed to use authorization grant 'client_credentials'."            | `invalid_grant`, "The OAuth 2.0 Client is marked as public and is thus not allowed to use authorization grant 'client_credentials'."                 | `client/client.go` (`GetGrantTypes`), `fosite/handler/oauth2/flow_client_credentials.go`                                                                                                          |
| Keycloak           | "Service account roles" (`serviceAccountsEnabled`) on the Client, off by default; enabling it creates a service account user.                                                                                     | `unauthorized_client`, HTTP 401, "Client not enabled to retrieve service account".                                       | `unauthorized_client`, HTTP 401, "Public client not allowed to retrieve service account".                                                            | `protocol/oidc/grants/ClientCredentialsGrantType.java`                                                                                                                                            |
| Spring AS          | `AuthorizationGrantType.CLIENT_CREDENTIALS` among the RegisteredClient's grant types, which have no default ("authorizationGrantTypes cannot be empty").                                                          | `unauthorized_client`, without a description.                                                                            | No check in the grant; a public Client is authenticated only for a token request with PKCE, so it gets `invalid_client` (**UNVERIFIED**).            | `client/RegisteredClient.java`, `authentication/OAuth2ClientCredentialsAuthenticationProvider.java`                                                                                               |
| Zitadel            | Not an OIDC application at all: `client_id` names a machine user ("service account") with a generated client secret.                                                                                              | `invalid_request` ("Errors.User.Machine.Secret.NotExisting") for a human user or a machine user without a secret.        | Not applicable: the machine user always has a secret.                                                                                                | `internal/api/oidc/client_credentials.go`, `internal/api/oidc/client.go`                                                                                                                          |
| Auth0              | A "client grant" authorizing the application for the API: "only applications with a client grant defined can get an access token for the API". The grant type is enabled on confidential applications by default. | Not stated.                                                                                                              | "Public applications cannot use the `client_credentials` grant type."                                                                                | [API access policies](https://auth0.com/docs/get-started/apis/api-access-policies-for-applications), [grant types](https://auth0.com/docs/get-started/applications/application-grant-types)       |
| Okta               | A service app ("API Services"), and an access policy rule of the custom authorization server whose grant types include it: "If no matching rule is found, then the authorization request fails."                  | Not stated.                                                                                                              | Not stated.                                                                                                                                          | [Client credentials](https://developer.okta.com/docs/guides/implement-grant-type/clientcreds/main/), [authorization servers](https://developer.okta.com/docs/guides/customize-authz-server/main/) |
| Microsoft Entra ID | "You must use application permissions, also known as app roles, that are granted by an admin or by the API's owner."                                                                                              | Not stated.                                                                                                              | Not stated.                                                                                                                                          | [Client credentials flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)                                                                            |

Every provider makes the grant something a Client is given rather than
has: off by default per Client in node-oidc-provider, Hydra, Keycloak and
Spring, and tied to an authorization per API in Auth0 and Entra. Three of
five open-source providers answer a Client not allowed with
`unauthorized_client`; node-oidc-provider and Zitadel use
`invalid_request`. Hydra and Keycloak refuse public Clients explicitly.

### Scopes

| Provider           | Which scopes a Client may get                                                                                                                                     | A scope outside them                                                                              | No `scope` sent                                                                                                                                                                    | `openid`                                                                                                      | Source                                                                                                                                                                                            |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| node-oidc-provider | Its "static" scopes, limited by the Client's `scope` metadata if set; with a `resource`, those of the Resource Server.                                            | `invalid_scope`, "requested scope is not allowed", for a static scope; an unknown one is dropped. | None: `scope: scopes.join(' ') \|\| undefined`.                                                                                                                                    | Passes through as a static scope (**UNVERIFIED**); no ID token.                                               | `lib/helpers/grant_authorization.js`, `lib/shared/check_resource.js`, `lib/actions/grants/client_credentials.js`                                                                                  |
| Ory Hydra          | The Client's `scope`, matched by the scope strategy (wildcard by default).                                                                                        | `invalid_scope`, "The OAuth 2.0 Client is not allowed to request scope '%s'."                     | None, unless `oauth2.client_credentials.default_grant_allowed_scope` is on, which grants all of the Client's scopes.                                                               | Granted if the Client has it; no ID token.                                                                    | `fosite/handler/oauth2/flow_client_credentials.go`, `oauth2/handler.go`, `driver/config/provider.go`                                                                                              |
| Keycloak           | The Client's default client scopes, plus optional ones requested; roles are the intersection of the Client's role scope mappings and the service account's roles. | `invalid_scope`, "Invalid scopes: ...".                                                           | The Client's default client scopes.                                                                                                                                                | Always allowed, and it adds an ID token.                                                                      | `protocol/oidc/grants/OAuth2GrantTypeBase.java`, `docs/documentation/server_admin/topics/clients/oidc/proc-using-a-service-account.adoc`                                                          |
| Spring AS          | The RegisteredClient's `scopes`.                                                                                                                                  | `invalid_scope`.                                                                                  | None.                                                                                                                                                                              | Allowed if registered; no ID token.                                                                           | `authentication/OAuth2ClientCredentialsAuthenticationValidator.java`                                                                                                                              |
| Zitadel            | OpenID Connect's scopes and its own `urn:zitadel:...` scopes; roles from the machine user's grants.                                                               | Dropped without an error.                                                                         | Refused, `invalid_request`: "The scope of your request is missing. Please ensure some scopes are requested."                                                                       | Allowed, and it adds an ID token, although a comment in `client_credentials.go` says "no id_token is issued". | `oidc/v3:pkg/op/auth_request.go`, `internal/api/oidc/token.go`                                                                                                                                    |
| Auth0              | "The permissions you define in the client grant are the ones the application is authorized to receive in the access token."                                       | Not stated.                                                                                       | Not stated. Under per-app authorization, "you must explicitly provide the required scopes as part of the token request."                                                           | Not stated.                                                                                                   | [Client grants](https://auth0.com/docs/get-started/applications/application-access-to-apis-client-grants)                                                                                         |
| Okta               | The scopes the access policy allows; "If any of the requested scopes are rejected by the Access Policies, the request is rejected."                               | Rejected (code not stated).                                                                       | `scope` "Must be at least one custom scope that you create", though the policy's default scopes may let a request leave it out.                                                    | "The Client Credentials flow never has a user context, so you can't request OpenID scopes."                   | [Client credentials](https://developer.okta.com/docs/guides/implement-grant-type/clientcreds/main/), [authorization servers](https://developer.okta.com/docs/guides/customize-authz-server/main/) |
| Microsoft Entra ID | The application permissions granted to the Client for the resource.                                                                                               | `invalid_scope`, "AADSTS70011".                                                                   | Required: `scope` is the resource's identifier "suffixed with .default", which grants "all the direct application permissions you have configured for your app" for that resource. | Not applicable.                                                                                               | [Client credentials flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)                                                                            |

Four of the five open-source providers keep a per-Client list of the
scopes it may get, and node-oidc-provider (for static scopes), Hydra,
Keycloak and Spring refuse a scope outside it with `invalid_scope`.
Without `scope`, the providers split: node-oidc-provider, Spring
and Hydra by default grant no scope; Keycloak grants the Client's
defaults; Zitadel and Okta refuse the request; Entra makes the `scope`
name the resource and so requires it.

### Audience

| Provider           | How the audience is chosen                                                                                                                                | Without it                                                                                                                                                                                                   | Source                                                                                                                                                         |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| node-oidc-provider | `resource`, through `getResourceServerInfo`; one value only for this grant ("only a single resource indicator value is supported for this grant type").   | No `aud`, so an opaque token: a JWT access token "must contain an audience, for Access Tokens without audience (only usable at the userinfo_endpoint) use an opaque format". `defaultResource` may name one. | `lib/actions/grants/client_credentials.js`, `lib/models/formats/jwt.js`                                                                                        |
| Ory Hydra          | Its own `audience` parameter, checked against the Client's `audience` list ("Requested audience '%s' has not been whitelisted by the OAuth 2.0 Client."). | An empty `aud`; nothing is refused.                                                                                                                                                                          | `fosite/audience_strategy.go`, `fosite/token/jwt/claims_jwt.go`                                                                                                |
| Keycloak           | Protocol mappers, such as the audience resolve mapper; `resource` only with the experimental `RESOURCE_INDICATORS` feature.                               | Whatever the mappers set, possibly no `aud`.                                                                                                                                                                 | `protocol/oidc/mappers/AudienceResolveProtocolMapper.java`, `protocol/oidc/resourceindicators/`                                                                |
| Spring AS          | Always the Client's own `client_id`, unless the application customizes the token.                                                                         | Not applicable.                                                                                                                                                                                              | `token/JwtGenerator.java`                                                                                                                                      |
| Zitadel            | A scope per project, `urn:zitadel:iam:org:project:id:{id}:aud`.                                                                                           | An empty `aud`.                                                                                                                                                                                              | `internal/api/oidc/token_client_credentials.go`                                                                                                                |
| Auth0              | `audience`, "required", "The unique identifier of the target API you want to access"; `resource` instead under a tenant compatibility profile.            | A tenant's "Default Audience", if set: "all access tokens issued by Auth0 will specify this API identifier as an audience". The error without either is not stated.                                          | [Get token](https://auth0.com/docs/api/authentication/client-credential-flow/get-token), [tenant settings](https://auth0.com/docs/get-started/tenant-settings) |
| Microsoft Entra ID | The `scope`, `{resource}/.default`: "All scopes included must be for a single resource. Including scopes for multiple resources will result in an error." | Not possible: `scope` is required.                                                                                                                                                                           | [Client credentials flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)                                         |

No open-source provider refuses a request that names no audience, but
none issues a JWT access token for a Resource Server without one: they
issue no audience, an opaque token, or a fixed one. Of the vendors, Auth0
and Entra require the request to name the API, by `audience` or by
`scope`.

### `sub`, refresh tokens, ID tokens, lifetime and discovery

| Provider           | `sub`                                                                                                                                                                                                      | Refresh token                                                                               | ID token                                         | Lifetime                                                                                        | `grant_types_supported`        | Source                                                                                                                                          |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------------------------------------------------ | ----------------------------------------------------------------------------------------------- | ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| node-oidc-provider | The `client_id`: `sub: sub \|\| clientId`. No check against Subjects found.                                                                                                                                | None.                                                                                       | None.                                            | `ClientCredentialsTTL`, ten minutes, against an hour for other access tokens.                   | Listed when the feature is on. | `lib/models/formats/jwt.js`, `lib/helpers/defaults.js`, `lib/actions/discovery.js`                                                              |
| Ory Hydra          | The `client_id`: `session.Subject = accessRequest.GetClient().GetID()`. No check found.                                                                                                                    | None.                                                                                       | None.                                            | `client_credentials_grant_access_token_lifespan` per Client, else `ttl.access_token`, one hour. | Always.                        | `oauth2/handler.go`, `client/client.go`                                                                                                         |
| Keycloak           | The service account user's id, a UUID like any user's; its username is `service-account-<clientId>`.                                                                                                       | Off by default; `client_credentials.use_refresh_token`, which is deprecated, turns it on.   | With `openid`.                                   | The Client's or realm's access token lifespan.                                                  | Always.                        | `protocol/oidc/grants/ClientCredentialsGrantType.java`, `server-spi-private/src/main/java/org/keycloak/protocol/oidc/OIDCConfigAttributes.java` |
| Spring AS          | The `client_id`: `.subject(principal.getName())`. No check found.                                                                                                                                          | None: "For the OAuth2 client_credentials grant, only an `OAuth2AccessToken` is associated." | None.                                            | `accessTokenTimeToLive` per Client, five minutes by default.                                    | Always.                        | `token/JwtGenerator.java`, `settings/TokenSettings.java`, `oidc/web/OidcProviderConfigurationEndpointFilter.java`                               |
| Zitadel            | The machine user's id, from the same user store as human users.                                                                                                                                            | None; `needRefreshToken` is `false`.                                                        | With `openid`.                                   | The instance's access token lifetime.                                                           | Listed.                        | `internal/api/oidc/token_client_credentials.go`, `internal/api/oidc/server.go`                                                                  |
| Auth0              | "For Machine-to-Machine apps using Client Credentials (no end user), the `sub` claim is a unique identifier for the app", for example `...@clients`, the `client_id` with a suffix; `gty` names the grant. | Not stated; the response documented holds `access_token`, `token_type` and `expires_in`.    | Not stated.                                      | Not surveyed.                                                                                   | Not surveyed.                  | [Access token profiles](https://auth0.com/docs/secure/tokens/access-tokens/access-token-profiles)                                               |
| Okta               | Not stated.                                                                                                                                                                                                | "The Client Credentials flow doesn't support refresh tokens."                               | Not possible: OpenID scopes cannot be requested. | Not surveyed.                                                                                   | Not surveyed.                  | [OAuth and OIDC concepts](https://developer.okta.com/docs/concepts/oauth-openid/)                                                               |
| Microsoft Entra ID | "a pairwise identifier that's unique to a particular application ID"; `oid` is "the verified identity of the user or service principal".                                                                   | "refresh tokens will never be granted with this flow".                                      | Not stated.                                      | Not surveyed.                                                                                   | Not surveyed.                  | [Access token claims](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference)                                  |

Two designs answer RFC 9700 §4.15:

- The `client_id` as `sub`, as RFC 9068 §2.2 suggests: node-oidc-provider,
  Hydra and Spring, and Auth0 with a suffix that no user identifier has.
  None of the three open-source providers checks the `client_id` against
  user identifiers; Auth0's suffix keeps the two apart by form.
- A user record for the Client, whose identifier is its `sub`: Keycloak
  and Zitadel. Clients and End-Users then share one namespace, and one
  identifier cannot be both.

No provider issues a refresh token by default; Keycloak can be configured
to, and calls the switch deprecated. Keycloak and Zitadel issue an ID
token when `openid` is requested, since a service account is a user for
them; the other three never do.

### UserInfo and revocation

- node-oidc-provider makes the grant's tokens revocable and introspectable
  (`ClientCredentials` is in `revokeable` and `introspectable`,
  `lib/actions/revocation.js`, `lib/actions/introspection.js`). At UserInfo
  it looks tokens up as `AccessToken`, so a client credentials token is not
  found there (**UNVERIFIED**), and "token audience prevents accessing the
  userinfo endpoint" refuses any token with an `aud`.
- Spring's UserInfo requires `openid` and an ID token in the authorization
  (`oidc/authentication/OidcUserInfoAuthenticationProvider.java`), so it
  refuses a client credentials token.
- Hydra's UserInfo checks only that the token is an access token
  (**UNVERIFIED** that it answers a client credentials token).
- Zitadel's integration tests call UserInfo with a machine user's token.

## The conformance suite

None of the plans pulsar runs, Config OP, Basic OP, Form Post Basic and
RP-Initiated Logout, sends `grant_type=client_credentials` or checks for
`client_credentials` in `grant_types_supported`. Under `openid/`, the only
matches are the Shared Signals modules in `openid/ssf/` and a comment in
`openid/client/AbstractOIDCCClientTest.java`.

The grant is tested by:

- FAPI 2.0 Final, with the `fapi_client_credentials_grant` profile
  (`variant/FAPI2FinalOPProfile.java`,
  `fapi2spfinal/ClientCredentialsGrantProfileBehavior.java`, which checks
  `grant_types_supported` with
  `FAPICheckDiscEndpointGrantTypesSupportedContainsClientCredentials`).
- FAPI 1 Advanced Final, FAPI 2.0 ID2 and FAPI-CIBA, in their open banking
  variants (`OpenBanking{Brazil,KSA,Uk}PreAuthorizationSteps` and others
  in `sequence/client/`).
- The Shared Signals transmitter modules
  (`openid/ssf/AbstractOIDSSFTransmitterTestModule.java`).

Adding the value to discovery would not change the Config OP plan's
result. `condition/client/OIDCCCheckDiscEndpointGrantTypesSupported.java`
fails only if `grant_types_supported` is not a non-empty array; the RFC
8414 schema that `ValidateServerMetadataAgainstSchema` applies gives it
`{"type":"array","items":{"type":"string"}}`, with no list of values; and
`CheckForUnexpectedParametersInServerMetadata` knows the key.

Source: <https://gitlab.com/openid/conformance-suite/-/tree/release-v5.3.4/src/main/java/net/openid/conformance/>.

## A consumer in `examples/`

`golang.org/x/oauth2/clientcredentials` (v0.38.0) implements the grant:

- `Config` has `ClientID`, `ClientSecret`, `TokenURL`, `Scopes`,
  `EndpointParams` and `AuthStyle`. `EndpointParams` "specifies additional
  parameters for requests to the token endpoint", so it carries `resource`.
  `scope` is sent only `if len(c.conf.Scopes) > 0`.
- It authenticates with a client secret only, in the header or in the
  body. With `AuthStyle` left at auto-detect, `internal.RetrieveToken`
  tries the header first and, on any error, sends the request again with
  the credentials in the body; the web app example sets
  `AuthStyleInHeader` to avoid that. `private_key_jwt` would need a new
  client assertion for each token request, which a fixed `EndpointParams`
  cannot hold; it would take a token source of the example's own that
  signs one with go-jose each time.
- `TokenSource` is a `ReuseTokenSource`, which requests a new token when
  the current one expires: "tokens received this way do not include a
  refresh token".

The API example (`examples/api/api.go`) needs no code change to serve a
token issued by this grant: it checks `iss`, `aud`, `exp`, `typ`, the
signature and the route's scope, none of which depends on an End-User,
and keeps notes by `sub`. With `sub` the `client_id`, a Client's notes
are its own, and apart from every End-User's, if no `client_id` can equal
a Subject. Its doc comment and README speak of "each End-User's notes"
and of "what the End-User allowed", which would need rewording.

## Recommendations

1. **Confidential Clients only.** pulsar refuses to start on a Client
   registered for the grant with `token_endpoint_auth_method` `none`, as
   RFC 6749 §4.4 and OAuth 2.1 §4.2 require; a public Client that asks
   gets `unauthorized_client`, as Keycloak answers it. Any method a
   confidential Client may register is allowed: `client_secret_basic`,
   `client_secret_post` or `private_key_jwt`. The README recommends
   `private_key_jwt`, after RFC 9700 §2.5 and MCP's extension.
2. **Opt in by `grant_types`.** A Client lists `grant_types`, with RFC
   7591's name and values. Left out, it means what every Client has
   today, `authorization_code` and `refresh_token`: a departure from RFC
   7591's default of `authorization_code` alone, to be recorded beside its
   requirement, so that existing registries keep working. A Client that
   uses this grant lists `["client_credentials"]` and nothing else, as
   RFC 7591 §5 allows ("it MAY disallow these two grant types from being
   registered together"): a Client then acts either for End-Users or for
   itself, never both, and a token's `sub` tells which. A Client that has
   not opted in gets `unauthorized_client` (RFC 6749 §5.2), as in Hydra,
   Keycloak and Spring. Every open-source provider surveyed leaves the
   grant off for a Client until it is given; Auth0 enables it on
   confidential applications by default, and Zitadel lets any machine
   user with a secret use it.
3. **The registry shape.** A Client registered for the grant:

   ```json
   {
     "client_id": "worker",
     "token_endpoint_auth_method": "client_secret_basic",
     "client_secret_hash": "$argon2id$v=19$m=19456,t=2,p=1$...$...",
     "grant_types": ["client_credentials"],
     "resource_servers": ["https://api.example/notes"],
     "scope": "notes:read notes:write"
   }
   ```

   - `scope`, RFC 7591's space-separated string, is required, and lists
     the scopes the Client may get. Each value must be a scope of a
     Resource Server in its `resource_servers`, each listed once. Since
     no Resource Server's scope is one of OpenID Connect's, `openid` can
     never be one. `scope` is not allowed on other Clients, whose scopes
     come from the End-User's consent.
   - `redirect_uris` and `post_logout_redirect_uris` are not allowed: RFC
     7591 §2 makes redirect URIs "for use in redirect-based flows", and
     the registry already refuses members that do nothing, such as
     `client_secret_hash` for `none`. Without one, such a Client cannot
     start an authorization request.
   - `client_id` must not be a UUID in the form of an End-User's Subject
     (recommendation 6).

   This keeps ADR 0001's static file and its strict decoding. It does not
   need ADR 0001 itself to change, but the choice of `sub` in
   recommendation 6 is hard to reverse once Resource Servers rely on it,
   so it is worth an ADR.

4. **`resource` is required.** A request without it gets
   `invalid_target`, the code RFC 8707 §2 names for a resource "missing",
   with §2.2 leaving the acceptable values to "local policy". It accepts
   one `resource`, a Resource Server the Client lists, as the code flow
   does (REQ-RESOURCE-4, REQ-RESOURCE-9). There is no per-Client default,
   and no default inferred from `scope`: the code flow does not infer one
   either (REQ-AT-14's departure), so one rule holds at the token endpoint,
   that a token for a Resource Server is one the Client named. Auth0
   requires `audience`, Entra makes the `scope` name the resource, and
   MCP's example requests carry `resource`; a token for pulsar's UserInfo
   would make no sense with no End-User, and no open-source provider
   issues a JWT for a Resource Server without being told which.
5. **`scope` is required, and checked against the registry.** RFC 6749
   §3.3 lets the server fail a request without `scope`, "indicating an
   invalid scope", rather than apply a default; RFC 9700 §2.3 asks for the
   minimum privileges; Okta and Zitadel refuse such a request too. So a
   request without `scope` gets `invalid_scope`. A value the Client's
   `scope` does not list, `openid` and every OpenID Connect scope
   included, gets `invalid_scope` (RFC 6749 §5.2), as in Hydra, Keycloak,
   Spring and node-oidc-provider, rather than being ignored. A value the
   Client may have, but of another Resource Server than the `resource`,
   gets `invalid_target`, "an invalid combination of resource and scope"
   (RFC 8707 §2). The scope granted is the scope requested, and the
   response sends it, as pulsar's always does.
6. **`sub` is the `client_id`, and cannot be a Subject.** RFC 9068 §2.2
   says it "SHOULD correspond to an identifier the authorization server
   uses to indicate the client application", as node-oidc-provider, Hydra
   and Spring have it; `client_id` stays as it is. RFC 9700 §4.15.1 and
   RFC 9068 §5 ask that a Client not choose a `client_id` that could pass
   for a resource owner. In pulsar no Client chooses its `client_id`; the
   operator writes it in the registry (ADR 0001). To keep even the
   operator from a collision, pulsar refuses to start on a Client
   registered for this grant whose `client_id` is a UUID in the lowercase
   hyphenated form `isUUID` accepts, the only form a Subject may take. The
   two namespaces are then apart by form, as Auth0's `@clients` suffix
   keeps them, and stay apart across edits to the registry while tokens
   issued before are still valid. A Resource Server can tell a Client's
   own token by `sub` equal to `client_id`, which no End-User's token can
   have; that answers §4.15.1's "other means for the resource server to
   distinguish", should it apply. Keycloak's and Zitadel's design, a user
   record per Client, does not fit a registry whose End-Users are people
   who sign in.
7. **One JWT access token, and nothing else.** The response holds
   `access_token`, `token_type`, `expires_in` and `scope`:
   - The access token is signed and typed as every other (REQ-AT-1,
     REQ-AT-2), with `aud` the Resource Server's identifier and the
     claims RFC 9068 §2.2 requires, and lives `TokenLifetime`, ten
     minutes, as node-oidc-provider's tokens of this grant do by default.
   - No refresh token: RFC 6749 §4.4.3 says one "SHOULD NOT be included",
     no provider issues one by default, and the Client can ask again.
   - No ID token: OpenID Connect Core §2 makes it a statement about an
     End-User's authentication, and recommendation 5 refuses `openid`.
     `tokenResponse.IDToken` becomes `omitempty`, and the access token is
     signed apart from the ID token.
   - The token is not recorded in `access_tokens`. UserInfo refuses it by
     its `aud` before any lookup (REQ-AT-8), and the revocation endpoint
     answers it with 200 and revokes nothing, as it does today for every
     token issued for a Resource Server (`TestRevokeAccessTokenClaims`);
     RFC 7009 §2 makes revoking access tokens a SHOULD, and §3 describes
     self-contained tokens that live until they expire. So no migration is
     needed.
8. **Discovery lists the grant.** `grant_types_supported` becomes
   `["authorization_code", "refresh_token", "client_credentials"]`
   (Discovery §3, RFC 8414 §2). The Config OP plan checks only that the
   list is a non-empty array of strings.
9. **The conformance suite does not test it.** No plan pulsar runs uses
   the grant; only FAPI, FAPI-CIBA open banking variants and Shared
   Signals do, and pulsar runs none of them. Its tests are pulsar's own.
10. **The consumer: a worker.** `examples/worker` and `examples/cmd/worker`:
    a job, a confidential Client with no End-User, that gets its own
    access token with `clientcredentials.Config`, `resource` in
    `EndpointParams` and `notes:write notes:read` in `Scopes`, and records
    each run as a note in the API, then lists its notes. It registers as
    `worker` with `client_secret_basic`, and sets `AuthStyleInHeader`, as
    the web app does; its secret is published in `examples/README.md`, as
    the web app's is. Its test, beside the CLI's in `examples_test.go`,
    proves over the wire that:
    - x/oauth2 gets a token with no refresh token, which the API accepts;
    - the token's `sub` and `client_id` are both `worker`, and its `aud`
      the API's identifier;
    - the worker's notes and the End-User's are kept apart: after the CLI
      adds a note as the End-User, the worker's list does not hold it, and
      the End-User's does not hold the worker's.

    The API needs no code change; its doc comment and README are reworded
    from "each End-User's notes" to each `sub`'s.

11. **AGENTS.md.** The row "Introspection (RFC 7662), `client_credentials`"
    loses `client_credentials`, once the worker example is its consumer;
    introspection stays, since the worker, like the API, needs none.

### Points for the maintainer

- Whether the worker authenticates with `client_secret_basic`, which
  x/oauth2 supports as it is, or with `private_key_jwt`, which RFC 9700
  §2.5 and MCP's extension recommend, at the cost of a token source of its
  own that signs a client assertion with go-jose for each request. No
  example uses `private_key_jwt` today.
- Recommendations 4 and 5 refuse what RFC 6749 §3.3 and RFC 8707 §2.1
  would let pulsar fill with a default: the Client's registered scopes,
  or its one Resource Server. Hydra offers the scope default as an
  option, and Keycloak applies one; Okta and Zitadel refuse. Least
  privilege and one rule for every grant argue for refusing; a Client
  with a single Resource Server and scope would find a default
  convenient.
- Recommendation 2 forbids one Client from using both this grant and the
  code flow, which Keycloak, Hydra and Auth0 allow. RFC 7591 §5 allows
  either.

## Size estimate

The code that changes:

- `internal/registry`: `grant_types` and `scope` on Clients, their checks
  at startup (public Clients, redirect URIs, scopes of the Client's
  Resource Servers, UUID-form `client_id`), and a method that reports
  whether a Client may use a grant; the package comment; tests.
- `internal/oidc/token.go`: a `client_credentials` branch in `exchange`,
  checking the form (`resource` present and once, `scope` present) before
  the Client authenticates, as the other grants do; then
  `unauthorized_client`, `invalid_target` and `invalid_scope` in turn; and
  signing an access token without an ID token, with `id_token` left out
  of the response.
- `internal/oidc/discovery.go`: `grant_types_supported`.
- `internal/server`: tests of the grant, and the two tests that use
  `client_credentials` as the unsupported grant, which move to another
  grant type rather than lose the case.
- `docs/requirements`: new IDs for RFC 6749 §4.4, §4.4.2, §4.4.3, the
  `unauthorized_client` code of §5.2 and §3.3; RFC 9068 §2.2's `sub` and
  §5; RFC 9700 §2.5 and §4.15.1; RFC 8707 §2's "missing"; and the RFC 7591
  default departure beside the registry's requirement.
- `README.md`: the paragraph on what pulsar does, and the one on the
  registry.
- `examples/`: the worker package and command, `registry.json`, the test,
  `README.md` and the API's README.
- `AGENTS.md`: the "Deliberately not doing" row.
- `docs/adr/`: one ADR for machine Clients and their `sub`.

A rough split into tickets, each depending on the one before:

1. **Registry**: `grant_types` and `scope`, with their checks, tests and
   the ADR. Small: around a hundred lines of code and as many of tests.
2. **Token endpoint and discovery**: the grant, its errors, the access
   token without an ID token, discovery, the requirement IDs and the
   README. Medium: the largest of the three, mostly in tests.
3. **The worker example**: the package, command, registry entry, test,
   READMEs and the AGENTS.md row. Small, and it runs only under
   `make examples`, which CI runs and the agent sandbox cannot.

Tickets 1 and 2 could be one, since the registry members do nothing
until the token endpoint reads them.

## Decision

#88 follows these recommendations. The maintainer settled the three points
left open on 2026-11-10:

- The worker authenticates with `private_key_jwt`, not the
  `client_secret_basic` of recommendation 10, so that the examples show the
  asymmetric client authentication RFC 9700 §2.5 recommends.
- `resource` and `scope` have no default, as recommendations 4 and 5 say.
- A Client uses this grant or the code flow, never both, as recommendation
  2 says.
