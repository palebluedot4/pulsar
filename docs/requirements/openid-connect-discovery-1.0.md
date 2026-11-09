# OpenID Connect Discovery 1.0

Clauses of [OpenID Connect Discovery 1.0 incorporating errata set 2](https://openid.net/specs/openid-connect-discovery-1_0.html)
that pulsar, as an OP, must or should meet. Issuer discovery by WebFinger
(§2) is not offered, so its clauses are not listed.

## Provider metadata (§3)

- REQ-DISC-1 (§3, `issuer`): "REQUIRED. URL using the https scheme with no
  query or fragment components that the OP asserts as its Issuer
  Identifier."

  Departure: pulsar also accepts an `http` issuer whose host is `localhost`
  or a loopback IP address, so that it can run on a developer's machine
  without a certificate. Every endpoint URL is derived from the issuer, so
  REQ-DISC-2 to REQ-DISC-5 share this exception. No other host can reach a
  loopback issuer, so a deployment that serves Clients cannot rely on it.

- REQ-DISC-2 (§3, `authorization_endpoint`): "REQUIRED. URL of the OP's
  OAuth 2.0 Authorization Endpoint [OpenID.Core]. This URL MUST use the
  https scheme and MAY contain port, path, and query parameter components."
- REQ-DISC-3 (§3, `token_endpoint`): "This is REQUIRED unless only the
  Implicit Flow is used. This URL MUST use the https scheme and MAY contain
  port, path, and query parameter components."
- REQ-DISC-4 (§3, `userinfo_endpoint`): "RECOMMENDED. URL of the OP's
  UserInfo Endpoint [OpenID.Core]. This URL MUST use the https scheme and
  MAY contain port, path, and query parameter components."
- REQ-DISC-5 (§3, `jwks_uri`): "REQUIRED. URL of the OP's JWK Set [JWK]
  document, which MUST use the https scheme."
- REQ-DISC-18 (§3, `jwks_uri`): "The JWK Set MUST NOT contain private or
  symmetric key values."
- REQ-DISC-6 (§3, `scopes_supported`): "RECOMMENDED. JSON array containing
  a list of the OAuth 2.0 [RFC6749] scope values that this server
  supports. [...] Servers MAY choose not to advertise some supported scope
  values even when this parameter is used, although those defined in
  [OpenID.Core] SHOULD be listed, if supported."

  pulsar lists `openid`, the four scopes that request claims, and
  `offline_access`.

- REQ-DISC-19 (§3, `grant_types_supported`): "OPTIONAL. JSON array
  containing a list of the OAuth 2.0 Grant Type values that this OP
  supports."

  pulsar lists `authorization_code` and `refresh_token`. It is not a
  Dynamic OpenID Provider, so the requirement of that clause to support
  `implicit` does not apply.

- REQ-DISC-7 (§3, `response_types_supported`): "REQUIRED. JSON array
  containing a list of the OAuth 2.0 response_type values that this OP
  supports."
- REQ-DISC-22 (§3, `response_modes_supported`): "OPTIONAL. JSON array
  containing a list of the OAuth 2.0 response_mode values that this OP
  supports, as specified in OAuth 2.0 Multiple Response Type Encoding
  Practices [OAuth.Responses]. If omitted, the default for Dynamic OpenID
  Providers is ["query", "fragment"]."

  pulsar lists `query` and `form_post`.

- REQ-DISC-8 (§3, `subject_types_supported`): "REQUIRED. JSON array
  containing a list of the Subject Identifier types that this OP supports."
- REQ-DISC-9 (§3, `id_token_signing_alg_values_supported`): "REQUIRED.
  [...] The algorithm RS256 MUST be included."
- REQ-DISC-10 (§3, `token_endpoint_auth_signing_alg_values_supported`):
  "Servers SHOULD support RS256. The value none MUST NOT be used."
- REQ-DISC-11 (§3, `claims_supported`): "RECOMMENDED. JSON array
  containing a list of the Claim Names of the Claims that the OpenID
  Provider MAY be able to supply values for."
- REQ-DISC-20 (§3): "The Token Endpoint, UserInfo Endpoint, jwks_uri
  endpoint, Dynamic Client Registration Endpoint, and any other endpoints
  directly accessed by Clients SHOULD support the use of Cross-Origin
  Resource Sharing (CORS) [CORS] and/or other methods as appropriate to
  enable JavaScript Clients and other Browser-Based Clients to access
  them."

  pulsar offers no Dynamic Client Registration. The origins each endpoint
  allows are those of REQ-BROWSER-1.

- REQ-DISC-21 (§3): "The use of CORS at the Authorization Endpoint is NOT
  RECOMMENDED as it is redirected to by the client and not directly
  accessed."

## RFC 8414 metadata

Members of the discovery document that
[RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) §2 defines, which an
OpenID Provider may also publish. Their IDs are numbered apart from
Discovery's.

- REQ-ASMETA-1 (RFC 8414 §2, `revocation_endpoint`): "OPTIONAL. URL of the
  authorization server's OAuth 2.0 revocation endpoint [RFC7009]."

  pulsar lists it, since it serves one (REQ-REVOKE-2).

- REQ-ASMETA-2 (RFC 8414 §2, `revocation_endpoint_auth_methods_supported`):
  "OPTIONAL. JSON array containing a list of client authentication methods
  supported by this revocation endpoint. [...] If omitted, the default is
  "client_secret_basic" -- the HTTP Basic Authentication Scheme specified
  in Section 2.3.1 of OAuth 2.0 [RFC6749]."

  pulsar lists the token endpoint's methods, `none` included, since a
  Client authenticates at both alike.

- REQ-ASMETA-3 (RFC 8414 §2,
  `revocation_endpoint_auth_signing_alg_values_supported`): "This metadata
  entry MUST be present if either of these authentication methods are
  specified in the "revocation_endpoint_auth_methods_supported" entry. No
  default algorithms are implied if this entry is omitted. The value "none"
  MUST NOT be used."

  `private_key_jwt` is listed, so it is present, with the algorithms of
  `token_endpoint_auth_signing_alg_values_supported` (REQ-DISC-10).

## Obtaining the configuration (§4)

- REQ-DISC-12 (§4): "OpenID Providers supporting Discovery MUST make a JSON
  document available at the path formed by concatenating the string
  /.well-known/openid-configuration to the Issuer."
- REQ-DISC-13 (§4.1): "If the Issuer value contains a path component, any
  terminating / MUST be removed before appending
  /.well-known/openid-configuration."

  pulsar refuses an issuer that ends with `/`, so there is never one to
  remove, and the issuer is exactly the discovery URL without its
  well-known suffix.

- REQ-DISC-14 (§4): "The openid-configuration endpoint SHOULD support the
  use of Cross-Origin Resource Sharing (CORS) [CORS] and/or other methods
  as appropriate to enable JavaScript Clients and other Browser-Based
  Clients to access it."
- REQ-DISC-15 (§4.2): "A successful response MUST use the 200 OK HTTP
  status code and return a JSON object using the application/json content
  type that contains a set of Claims as its members that are a subset of
  the Metadata values defined in Section 3."
- REQ-DISC-16 (§4.2): "Claims with zero elements MUST be omitted from the
  response."
- REQ-DISC-17 (§4.3): "The issuer value returned MUST be identical to the
  Issuer URL that was used as the prefix to
  /.well-known/openid-configuration to retrieve the configuration
  information."
