# The audience of a client assertion

What the specifications in scope, the OpenID Foundation, the conformance
suite and other providers say about the `aud` of a `private_key_jwt`
client assertion, after the audience injection attack disclosed in
January 2025 (#39). Surveyed 2026-11-09 from specifications, official
documentation and official source code. Anything not confirmed is marked
**UNVERIFIED**.

## The attack

A Client that authenticates with the same key to more than one
authorization server can be led by a malicious one to sign an assertion
whose audience is another server's token endpoint: the malicious server
publishes that URL as its own token endpoint, or as another of its
endpoints. It then presents the assertion at the other server, as the
Client. RFC 7523 §3 let a server accept its token endpoint URL, and OpenID
Connect Core 1.0 §9 told Clients to send it, so the assertion is accepted.
The OpenID Foundation announced the vulnerability on 2025-02-25 as
CVE-2025-27370 (OpenID Connect Core) and CVE-2025-27371 (RFC 7521 and
RFC 7523). The issuer identifier is not open to the same substitution:
RFC 8414 §3.3 has the Client validate the issuer in the metadata it
retrieves, while "Other endpoint values of the metadata cannot be directly
validated" (RFC 10070 §1).

## Normative text

| Source                                                       | Clause                                                             | What it says                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ------------------------------------------------------------ | ------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| RFC 10070 (Proposed Standard, November 2026)                 | §4, RFC 7523 §3 item 3 as replaced, case B (client authentication) | "For client authentication, the "aud" (audience) claim value MUST use the issuer identifier [RFC8414] of the authorization server as its sole value. [...] this includes that the token endpoint URL of the authorization server MUST NOT be used as an audience value. The authorization server MUST reject any JWT that does not contain its issuer identifier as its sole audience value." Values are compared by Simple String Comparison (RFC 3986 §6.2.1). |
| RFC 10070                                                    | §4                                                                 | "Client authentication JWTs SHOULD be explicitly typed by using the "typ" header parameter value "client-authentication+jwt" [...]" and, since typing "does not prevent the attacks", "it is NOT RECOMMENDED for servers to reject JWTs that do not have explicit types."                                                                                                                                                                                        |
| RFC 10070                                                    | §2, replacing RFC 7521 §5.1                                        | Audience is "A value that identifies the party intended to process the assertion. The issuer identifier of the authorization server [...] can be used to indicate that the authorization server is a valid intended audience". The sentence naming the token endpoint URL is removed.                                                                                                                                                                            |
| RFC 10070                                                    | §6                                                                 | "some clients implementing earlier versions may not interoperate with authorization servers that strictly enforce the updated requirements". No transition period is defined.                                                                                                                                                                                                                                                                                    |
| draft-ietf-oauth-rfc7523bis-11                               | Document history, -03                                              | "Do not restrict the "aud" claim's type. Allow it to be an array with a single member."                                                                                                                                                                                                                                                                                                                                                                          |
| OpenID Connect Core 1.0 incorporating errata set 2 (final)   | §9                                                                 | "The Authorization Server MUST verify that it is an intended audience for the token. The Audience SHOULD be the URL of the Authorization Server's Token Endpoint." Unchanged since 2023-12-15.                                                                                                                                                                                                                                                                   |
| OpenID Connect Core 1.0, draft 36 incorporating errata set 3 | §9                                                                 | "The Authorization Server MUST verify that it is the sole audience for the token. The Audience value MUST be the OP's Issuer Identifier passed as a string, and not a single-element array." Not approved: openid/connect issue #2157, opened 2026-11-05, debates whether to publish it as errata or as Connect 1.1.                                                                                                                                             |
| FAPI 2.0 Security Profile (final, 2025-02-22)                | §5.3.2.1                                                           | The authorization server "shall only accept its issuer identifier value (as defined in [RFC8414]) as a string in the aud claim received in client authentication assertions".                                                                                                                                                                                                                                                                                    |
| OpenID Federation 1.0 (2026-02-17)                           | §12.1.1.2                                                          | The audience "MUST be the Entity Identifier of the OP and MUST NOT include any other values."                                                                                                                                                                                                                                                                                                                                                                    |
| OpenID CIBA Core 1.0                                         | §7.1                                                               | Unchanged: the OP "MUST accept its Issuer Identifier, Token Endpoint URL, or Backchannel Authentication Endpoint URL". pulsar offers no CIBA.                                                                                                                                                                                                                                                                                                                    |
| OAuth 2.1, draft-ietf-oauth-v2-1-17                          | §2.4                                                               | "clients and authorization servers MUST follow the updated guidance around aud values in [I-D.ietf-oauth-rfc7523bis]."                                                                                                                                                                                                                                                                                                                                           |
| RFC 9700                                                     | —                                                                  | Nothing on the audience of a client assertion; it predates the disclosure.                                                                                                                                                                                                                                                                                                                                                                                       |

The OpenID Foundation's disclosure notice of 2025-01-24 asked
authorization servers to "only accept its own AS Issuer identifier value
as a string in the aud claim". Hosseyni, Küsters and Würtele, "Audience
Injection Attacks" (IACR ePrint 2025/629), describes the attack; its
recommendations were not read directly (**UNVERIFIED**), and RFC 10070
cites it.

Sources: <https://www.rfc-editor.org/rfc/rfc10070>,
<https://www.ietf.org/archive/id/draft-ietf-oauth-rfc7523bis-11.txt>,
<https://openid.net/specs/openid-connect-core-1_0.html>,
<https://openid.net/specs/openid-connect-core-1_0-36.html>,
<https://github.com/openid/connect/issues/2157>,
<https://openid.net/specs/fapi-security-profile-2_0-final.html>,
<https://openid.net/specs/openid-federation-1_0.html>,
<https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html>,
<https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/>,
<https://openid.net/notice-of-a-security-vulnerability/>,
<https://openid.net/wp-content/uploads/2025/01/OIDF-Responsible-Disclosure-Notice-on-Security-Vulnerability-for-private_key_jwt.pdf>,
<https://eprint.iacr.org/2025/629>.

## The conformance suite

At `release-v5.3.4`, the version pulsar runs:

- `oidcc-basic-certification-test-plan` (`OIDCCBasicTestPlan.java`) fixes
  `client_auth_type` to `client_secret_basic`, with one module run with
  `client_secret_post`. No module uses `private_key_jwt`.
- `oidcc-config-certification-test-plan` reads discovery only, with no
  client authentication.
- Where an OpenID Connect plan does use `private_key_jwt`, the assertion's
  `aud` is the token endpoint URL as a string
  (`condition/client/CreateClientAuthenticationAssertionClaims.java`). The
  Dynamic OP plan forces `private_key_jwt`, so a provider that accepts the
  issuer alone fails it (panva/node-oidc-provider issue #1499).
  `OIDCCEnsureClientAssertionWithIssAudSucceeds` sends the issuer, and
  only warns if it is refused.
- FAPI 2.0 plans refuse the opposite way:
  `FAPI2SPFinalEnsureInvalidClientAssertionsFail` expects a token endpoint
  `aud`, a PAR endpoint `aud` and an array of the issuer and another value
  to fail with `invalid_client` or `invalid_request`.

Source: <https://gitlab.com/openid/conformance-suite/-/tree/release-v5.3.4>.

## Other providers

| Provider                    | What it accepts as `aud`                                                                                                             | Since the disclosure                                                                                                                                                                                         |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Keycloak 26.2+              | A single value: the issuer, or its token, introspection or another endpoint URL                                                      | Single audience by default since 26.2 (April 2025), with `allow-multiple-audiences-for-jwt-client-authentication` to restore the old behavior, which "might be removed in the future"; recommends the issuer |
| Duende IdentityServer 7.2   | The issuer, or its token, CIBA or PAR endpoint URL                                                                                   | `StrictClientAssertionAudienceValidation`, off by default, accepts the issuer alone; a `typ` of `client-authentication+jwt` turns it on for that request                                                     |
| Authlete 3.0                | Configurable                                                                                                                         | `clientAssertionAudRestrictedToIssuer`, "issuer [...] as a string"; its default is **UNVERIFIED**                                                                                                            |
| node-oidc-provider 9.13     | The issuer, the token endpoint or the endpoint called; an array if any member matches; the issuer alone, as a string, under FAPI 2.0 | A hook, `assertJwtClientAuthClaimsAndHeader`, for stricter checks                                                                                                                                            |
| Spring Authorization Server | The issuer, or its token, introspection, revocation or PAR endpoint URL; an array if any member matches                              | None found                                                                                                                                                                                                   |
| Ory Hydra                   | Its token endpoint URLs, not the issuer; arrays allowed                                                                              | None found                                                                                                                                                                                                   |
| Okta                        | "The full URL of the resource you're using the JWT to authenticate to", as a string                                                  | None documented                                                                                                                                                                                              |

Sources: <https://www.keycloak.org/docs/latest/upgrading/>,
<https://docs.duendesoftware.com/identityserver/>,
<https://github.com/authlete/authlete-java-common>,
<https://github.com/panva/node-oidc-provider/blob/main/lib/shared/jwt_client_auth.js>,
<https://github.com/spring-projects/spring-security>,
<https://github.com/ory/hydra>,
<https://developer.okta.com/docs/guides/build-self-signed-jwt/>.

## Conclusion

- RFC 10070 is published and updates RFC 7523, which is in scope; OAuth
  2.1 points to it too. Following it is meeting a specification, not
  running ahead of one.
- Its rule satisfies the one requirement OpenID Connect Core 1.0 §9 puts
  on the server, "MUST verify that it is an intended audience". It departs
  from the SHOULD put on the Client: a Client that sends the token endpoint
  URL, as §9 says to, is refused.
- The sole value may be a string or an array of one: RFC 10070 does not
  restrict the type. FAPI 2.0 and the unapproved errata set 3 require a
  string.
- The Basic OP and Config OP plans do not use `private_key_jwt`, so
  restricting the audience does not change their results.
