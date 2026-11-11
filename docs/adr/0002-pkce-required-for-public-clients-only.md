# PKCE is required for public Clients only

pulsar requires PKCE only of public Clients, although requiring it of every
Client would be the simpler rule. RFC 9700 §2.1.1 lets a confidential
OpenID Connect Client rely on `nonce` instead. The OpenID conformance suite's
Basic OP plan depends on that allowance: it sends a `code_challenge` in only
one module (`oidcc-ensure-request-with-valid-pkce-succeeds`), and
`oidcc-ensure-request-without-nonce-succeeds-for-code-flow` requires success
with neither a nonce nor PKCE. Requiring PKCE of every Client would therefore
fail the Basic OP plan (suite `release-v5.3.4`, `OIDCCBasicTestPlan.java` and
`AbstractOIDCCServerTest.java`).

pulsar supports only `S256`. A `code_challenge` without a
`code_challenge_method` means `plain` (RFC 7636 §4.3), so it is refused at the
authorization endpoint like any other unsupported method. Whenever an
authorization request carries a `code_challenge`, the token request must present
a matching verifier. A token request that sends a `code_verifier` for a code
issued without a challenge is rejected, which RFC 9700 §2.1.1 requires as a
defense against PKCE downgrade.
