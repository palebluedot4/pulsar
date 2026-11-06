# OpenID Connect Core 1.0

Clauses of [OpenID Connect Core 1.0 incorporating errata set 2](https://openid.net/specs/openid-connect-core-1_0.html)
that pulsar, as an OP, must or should meet.

## ID Token (§2)

- REQ-CORE-1 (§2, `sub`): "Subject Identifier. A locally unique and never
  reassigned identifier within the Issuer for the End-User ... It MUST NOT
  exceed 255 ASCII [RFC20] characters in length. The sub value is a
  case-sensitive string."
