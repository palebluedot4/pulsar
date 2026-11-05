# PKCE is required for public clients only

pulsar requires PKCE only of public clients, although requiring it of every
client would be the simpler rule. RFC 9700 §2.1.1 lets a confidential
OpenID Connect client rely on `nonce` instead. The OpenID conformance suite's
Basic OP plan depends on that allowance: it sends a `code_challenge` in only
one module (`oidcc-ensure-request-with-valid-pkce-succeeds`), and
`oidcc-ensure-request-without-nonce-succeeds-for-code-flow` requires success
with neither a nonce nor PKCE. Requiring PKCE of every client would therefore
fail the Basic OP plan (suite `release-v5.3.4`, `OIDCCBasicTestPlan.java` and
`AbstractOIDCCServerTest.java`).

pulsar supports only `S256`. Whenever an authorization request carries a
`code_challenge`, the token request must present a matching verifier. A
token request that sends a `code_verifier` for a code issued without a
challenge is rejected, which RFC 9700 §2.1.1 requires as a defense against
PKCE downgrade.
