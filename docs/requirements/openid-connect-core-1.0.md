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

## ID Token for the Authorization Code Flow (§3.1.3.6)

- REQ-CORE-7 (§3.1.3.6, `at_hash`): "Its value is the base64url encoding of
  the left-most half of the hash of the octets of the ASCII representation
  of the access_token value, where the hash algorithm used is the hash
  algorithm used in the alg Header Parameter of the ID Token's JOSE
  Header."

  `at_hash` is OPTIONAL in this flow; pulsar always includes it.

## Request objects (§6)

- REQ-CORE-8 (§6.1): "Should an OP not support this parameter and an RP
  uses it, the OP MUST return the request_not_supported error."
- REQ-CORE-9 (§6.2): "Should an OP not support this parameter and an RP
  uses it, the OP MUST return the request_uri_not_supported error."
