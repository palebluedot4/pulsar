# Signing algorithms: ES256 and EdDSA beside RS256

Surveyed 2026-11-10. It asks whether, and how, pulsar should sign ID tokens and
access tokens with ES256 and EdDSA as well as RS256. It covers these
questions: what the specifications require and allow; whether `EdDSA` has
been replaced by a fully specified `Ed25519`, and which name pulsar should
publish; who chooses the algorithm for each token, and what other providers
do; what the Go libraries pinned in this repository support; what changes in
key generation, storage and rotation; whether the conformance plans pulsar
runs exercise any algorithm but RS256; and how large the work is.

Specifications were read at these versions:

- OpenID Connect Core 1.0, Discovery 1.0 and Dynamic Client Registration 1.0,
  each "incorporating errata set 2"
- OpenID Connect Token Hash Algorithm Implementer's Guide 1.0, draft 00
  (published 2026-09-04)
- RFC 7518, RFC 8037, RFC 8414, RFC 8725, RFC 9068, and RFC 9864 (October 2025)

Libraries were read from the Go module cache at the versions this
repository pins: `github.com/go-jose/go-jose/v4` v4.1.8 (`go.mod`) and v4.1.9
(`examples/go.mod`), `github.com/coreos/go-oidc/v3` v3.21.0 and
`golang.org/x/oauth2` v0.38.0 (`examples/go.mod`). v4.1.9 and v3.21.0 are each
project's latest release on 2026-11-10.

The OpenID conformance suite was read at `release-v5.3.4`, commit
`23353b36957d6466010de767c812d2c91ed37638`, with paths under
`src/main/java/net/openid/conformance/`, as in the
[earlier survey](logout-revocation-resources.md). Open-source providers were
read from source at these commits:

- node-oidc-provider 9.13.3, `3ed87bef95d0f02b72917b9eb7d17ef5c3b2313b`
- Ory Hydra `master`, `4174065ffb052799890f7480f5360a877a67ffc1`
- Keycloak `main`, `e649c7732498971ddc8254e9a9f2b65428aa8b17`
- Spring Authorization Server, in Spring Security `main`,
  `fc7249dc7afba47d30dd1877d0634401b1fd98da`, module
  `oauth2/oauth2-authorization-server`
- Zitadel v4.20.2, `dce17d591309b1c0cdfb6c6718ec6cfada05eb7d` (released
  2026-11-09)

The first four are the development heads the earlier survey read, not
releases. Managed services were read from their documentation by URL, and
from their live discovery documents, fetched on 2026-11-10. Anything not
confirmed is marked **UNVERIFIED**.

## What pulsar does today

- `internal/signing` signs every JWT with one constant, `algorithm =
jose.RS256`. It generates RSA-2048 keys, accepts only RSA keys of at least
  2048 bits when it decrypts one, and publishes each key with `alg: RS256`.
  `KeySet.Active` returns one key, and a key's successor is the next row in
  `ListSigningKeys`, ordered by `activates_at`.
- `VerifyJWT` and `VerifyIDTokenHint` parse with `[]jose.SignatureAlgorithm{
jose.RS256}`; `idTokenSubject` in `internal/oidc/authorize.go` does too.
- `accessTokenHash` in `internal/oidc/token.go` always hashes with SHA-256.
- Discovery lists `id_token_signing_alg_values_supported: ["RS256"]`.
- The table `signing_keys` (migrations 00002 and 00010) has no column for
  the algorithm.
- The registry already accepts RS256, PS256 and ES256 for the keys Clients
  register for `private_key_jwt` (`registry.AssertionAlgorithms`); that list
  is about verifying Clients, not about what pulsar signs.
- `examples/api/api.go` accepts only RS256 access tokens. The web app and the
  CLI verify ID tokens through go-oidc's `Provider.Verifier` without setting
  `SupportedSigningAlgs`.

## What the specifications say

### OpenID Connect

| Clause                                                 | What it says                                                                                                                                                                                                                                                                                                                                                                                |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Core §15.1                                             | "OPs MUST support signing ID Tokens with the RSA SHA-256 algorithm (an alg value of RS256), unless the OP only supports returning ID Tokens from the Token Endpoint (as is the case for the Authorization Code Flow) and only allows Clients to register specifying none as the requested ID Token signing algorithm."                                                                      |
| Core §10.1                                             | "The private key used to sign the content MUST be associated with a public key used for signature verification published by the sender in its JWK Set document. If there are multiple keys in the referenced JWK Set document, a kid value MUST be provided in the JOSE Header."                                                                                                            |
| Core §10.1.1                                           | Rotation by adding keys to the JWK Set; the verifier "knows to go back to the jwks_uri location to re-retrieve the keys when it sees an unfamiliar kid value."                                                                                                                                                                                                                              |
| Core §3.1.3.7, step 6                                  | "The alg value SHOULD be the default of RS256 or the algorithm sent by the Client in the id_token_signed_response_alg parameter during Registration."                                                                                                                                                                                                                                       |
| Core §3.1.3.6, `at_hash`                               | "the hash algorithm used is the hash algorithm used in the alg Header Parameter of the ID Token's JOSE Header. For instance, if the alg is RS256, hash the access_token value with SHA-256".                                                                                                                                                                                                |
| Discovery §3, `id_token_signing_alg_values_supported`  | "REQUIRED. JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for the ID Token to encode the Claims in a JWT. The algorithm RS256 MUST be included."                                                                                                                                                                                               |
| Discovery §3, `userinfo_signing_alg_values_supported`  | "OPTIONAL." pulsar returns UserInfo as JSON only, so this does not apply.                                                                                                                                                                                                                                                                                                                   |
| Registration §2, `id_token_signed_response_alg`        | "OPTIONAL. JWS alg algorithm [JWA] REQUIRED for signing the ID Token issued to this Client. The value none MUST NOT be used as the ID Token alg value unless the Client uses only Response Types that return no ID Token from the Authorization Endpoint (such as when only using the Authorization Code Flow). The default, if omitted, is RS256."                                         |
| Registration §2, `userinfo_signed_response_alg`        | "OPTIONAL. JWS alg algorithm [JWA] REQUIRED for signing UserInfo Responses. If this is specified, the response will be JWT serialized". Without it, UserInfo answers JSON, as pulsar's does.                                                                                                                                                                                                |
| Token Hash Algorithm Implementer's Guide, draft 00, §2 | "When EdDSA is used, implementations MUST determine the EdDSA parameter set from the key used to validate the ID Token signature, such as the JWK crv value". Table 1: SHA-256 for RS256 and ES256; SHA-512 for `EdDSA` with an Ed25519 key, and for `Ed25519`. Its abstract: "It is intended to remain open for maintenance and is not intended to advance to Final Specification status." |

So RS256 stays mandatory and listed. Any other algorithm is optional, and
the specifications' model is that each Client chooses its ID token
algorithm, by `id_token_signed_response_alg`, with RS256 as the default.
pulsar's registry is a static file (ADR 0001), not Dynamic Client
Registration, but the Client metadata names are the same.

Sources: <https://openid.net/specs/openid-connect-core-1_0.html>,
<https://openid.net/specs/openid-connect-discovery-1_0.html>,
<https://openid.net/specs/openid-connect-registration-1_0.html>,
<https://openid.net/specs/openid-connect-token-hash-algorithms-1_0.html>.

### Access tokens: RFC 9068 and RFC 8414

- RFC 9068 §2.1: "JWT access tokens MUST NOT use "none" as the signing
  algorithm." "Authorization servers and resource servers conforming to this
  specification MUST include RS256 (as defined in [RFC7518]) among their
  supported signature algorithms."
- RFC 9068 §4: "Authorization servers SHOULD use OAuth 2.0 Authorization
  Server Metadata [RFC8414] to advertise to resource servers their signing
  keys via "jwks_uri"". "An authorization server MAY elect to use different
  keys to sign OpenID Connect ID Tokens and JWT access tokens. This
  specification does not provide a mechanism for identifying a specific key
  as the one used to sign JWT access tokens. An authorization server can sign
  JWT access tokens with any of the keys advertised via authorization server
  (AS) metadata or OpenID Connect discovery."
- RFC 9068 §5: "Given that resource servers have no way of knowing what key
  should be used to validate JWT access tokens in particular, they have to
  accept signatures performed with any of the keys published in AS metadata
  or OpenID Connect discovery; consequently, an attacker just needs to
  compromise any key among the ones published to be able to generate and sign
  JWTs that will be accepted as valid by the resource server."
- RFC 8414 §2 defines `*_auth_signing_alg_values_supported` for client
  authentication only. No metadata for the algorithm of access tokens was
  found in RFC 8414 or RFC 9068.

So a Resource Server learns the algorithm only from the token's header and
the key its `kid` names, and checks it against an allow-list of its own.
Which algorithm a given Resource Server's tokens use is a matter of
configuration between it and the authorization server.

Sources: <https://www.rfc-editor.org/rfc/rfc9068>,
<https://www.rfc-editor.org/rfc/rfc8414>.

### The algorithms: RFC 7518, RFC 8037 and RFC 9864

- RFC 7518 §3.1 lists ES256, "ECDSA using P-256 and SHA-256", as
  "Recommended+", where "+" "indicates that the requirement strength is likely
  to be increased in a future version"; RS256 is "Recommended". §3.4 defines
  the signature as R and S, "256-bit unsigned integers", concatenated, not
  DER.
- RFC 8037 §3.1: "algorithm "EdDSA" is defined here, to be applied as the
  value of the "alg" parameter." "The key type used with these keys is "OKP"
  and the algorithm used for signing is "EdDSA"." "The EdDSA variant used is
  determined by the subtype of the key (Ed25519 for "Ed25519" and Ed448 for
  "Ed448")."
- RFC 9864 (Standards Track, October 2025, updates RFCs 7518, 8037 and 9053)
  calls EdDSA "polymorphic": "Those requiring information beyond the
  algorithm identifier to determine the cryptographic operations to be
  performed." Of negotiation by `alg` values, as Discovery does: "This does
  not work for polymorphic algorithms. For instance, with EdDSA, it is not
  known which of the curves Ed25519 and/or Ed448 are supported."
  - §2.2 registers the JOSE algorithm `Ed25519`, "EdDSA using the Ed25519
    parameter set in Section 5.1 of [RFC8032]", JOSE Implementation
    Requirements "Optional".
  - §4.1.2: "IANA has updated the status to "Deprecated" for the following
    registration": `EdDSA`.
  - §4.4 defines Deprecated: "There is a preferred mechanism to achieve
    functionality similar to that referenced by the identifier; this
    replacement functionality SHOULD be utilized in new deployments in
    preference to the deprecated identifier, unless there exist documented
    operational or regulatory requirements that prevent migration away from
    the deprecated identifier." Prohibited, by contrast, means "MUST NOT be
    used".
  - §5: the key representation is unchanged, "except that the "alg" value
    would be Ed25519 rather than EdDSA, if included."
  - §2.1: ES256 in JOSE is already fully specified ("The corresponding JOSE
    registrations in [RFC7518] are fully specified"); only COSE's ES256 is
    deprecated, for ESP256.

So `EdDSA` is deprecated, not prohibited. RFC 9864 says new deployments
SHOULD publish `Ed25519` unless documented operational requirements prevent
it. ES256 is unaffected.

Sources: <https://www.rfc-editor.org/rfc/rfc7518>,
<https://www.rfc-editor.org/rfc/rfc8037>,
<https://www.rfc-editor.org/rfc/rfc9864>.

### RFC 8725

- §3.1: "Libraries MUST enable the caller to specify a supported set of
  algorithms and MUST NOT use any other algorithms when performing
  cryptographic operations. [...] Moreover, each key MUST be used with
  exactly one algorithm, and this MUST be checked when the cryptographic
  operation is performed." pulsar records this as REQ-JWTBCP-1 for Client
  keys; it applies to pulsar's own keys too once they are of several types.
- §3.2: "applications MUST only allow the use of cryptographically current
  algorithms that meet the security requirements of the application. [...]
  Applications MUST therefore be designed to enable cryptographic agility."

Source: <https://www.rfc-editor.org/rfc/rfc8725>.

## Who chooses the algorithm, and what providers offer

| Provider           | ES256     | EdDSA     | `Ed25519` | Who chooses                                                                                                                                                                                   | Default | `at_hash` with EdDSA                                                                                             | Source                                                                                                                                                                   |
| ------------------ | --------- | --------- | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| node-oidc-provider | Yes       | Yes       | Yes       | ID tokens: the Client, by `id_token_signed_response_alg`. Access tokens: the Resource Server, by `jwt.sign.alg` in what `getResourceServerInfo` returns.                                      | RS256   | SHA-512 (`getHashArgs`: `case 'Ed25519': case 'EdDSA': // alias for Ed25519, Ed448 is not supported`)            | `lib/helpers/defaults.js` (`enabledJWA.idTokenSigningAlgValues: ['RS256', 'PS256', 'ES256', 'Ed25519', 'EdDSA']`), `lib/models/id_token.js`, `lib/models/formats/jwt.js` |
| Keycloak           | Yes       | Yes       | No        | The Client (`id.token.signed.response.alg`, `access.token.signed.response.alg`), then the realm's default, then RS256.                                                                        | RS256   | SHA-512 for Ed25519, SHAKE256 for Ed448 (`JavaAlgorithm.getJavaAlgorithmForHash`)                                | `core/.../crypto/Algorithm.java`, `server-spi-private/.../OIDCConfigAttributes.java`, `services/.../jose/jws/DefaultTokenManager.java`                                   |
| Ory Hydra          | Yes       | Yes       | No        | One choice per key set: the first private key of `hydra.openid.id-token` for ID tokens, of `hydra.jwt.access-token` for access tokens. No `id_token_signed_response_alg` on Clients.          | RS256   | SHA-256: `ComputeHash` reads the size from `alg[2:]`, which for `EdDSA` does not parse. Read from code, not run. | `cmd/cmd_create_jwks.go`, `jwk/helper.go`, `client/client.go`, `fosite/handler/openid/helper.go`                                                                         |
| Spring AS          | Yes       | No        | No        | ID tokens: the registered Client, by `TokenSettings.idTokenSignatureAlgorithm`. Access tokens: fixed RS256 in `JwtGenerator`. Discovery hard-codes `RS256`.                                   | RS256   | Not applicable; no `at_hash` found in the module                                                                 | `oauth2-jose/.../jws/SignatureAlgorithm.java`, `token/JwtGenerator.java`, `OidcProviderConfigurationEndpointFilter.java`                                                 |
| Zitadel            | Yes       | Yes       | No        | The instance: one active web key; "There can be only one active key on an instance."                                                                                                          | RS256   | SHA-512 (zitadel/oidc `GetHashAlgorithm`, `case jose.EdDSA`)                                                     | `internal/crypto/web_key.go`, `internal/command/web_key.go`, `cmd/defaults.yaml`, <https://zitadel.com/docs/guides/integrate/login/oidc/webkeys>                         |
| Auth0              | No        | No        | No        | ID tokens: the Application ("select the appropriate signing algorithm for the application"); RS256, HS256 or PS256. Access tokens: the API, "HS256 and RS256", fixed when the API is created. | —       | —                                                                                                                | <https://auth0.com/docs/get-started/applications/signing-algorithms>, <https://auth0.com/docs/get-started/apis/api-settings>                                             |
| Okta               | No        | No        | No        | None: the ID and access token `alg` "is always RS256".                                                                                                                                        | RS256   | —                                                                                                                | <https://developer.okta.com/docs/api/openapi/okta-oauth/guides/overview>                                                                                                 |
| Microsoft Entra ID | Not found | Not found | No        | None found. Live discovery lists `["RS256"]`; its JWK Set holds RSA keys only.                                                                                                                | RS256   | —                                                                                                                | <https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference>, <https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration>  |
| Google             | No        | No        | No        | None. Live discovery lists `["RS256"]`.                                                                                                                                                       | RS256   | —                                                                                                                | <https://accounts.google.com/.well-known/openid-configuration>                                                                                                           |

Keycloak, node-oidc-provider and Zitadel publish keys of several algorithms
in one JWK Set at once; Hydra publishes its ID token and access token sets
together. Every provider defaults to RS256. Of the five open-source
providers, three let a Client choose its ID token algorithm; Hydra and
Zitadel make one choice for all. For access tokens, node-oidc-provider lets
the Resource Server choose, Keycloak the Client, and Spring and Hydra make
one choice. No managed service surveyed signs with ES256 or EdDSA. Only
node-oidc-provider signs with `Ed25519`; Keycloak, Hydra and Zitadel publish
`EdDSA`.

## Libraries

### go-jose v4.1.8 and v4.1.9

- `shared.go` defines `EdDSA`, `ES256`, `RS256`, PS256 and the rest, and
  ML-DSA-44/65/87; it defines no `Ed25519` signature algorithm in either
  version. `newEd25519Signer` and the Ed25519 verifier (`asymmetric.go`)
  refuse any algorithm but `EdDSA`. So go-jose can neither sign nor verify a
  JWS whose `alg` is `Ed25519`.
- Issue go-jose/go-jose#330, "Support the fully specified Ed25519 JWS
  algorithm (RFC 9864)", opened 2026-11-06, is open.
- `makeJWSRecipient` signs with a concrete `ed25519.PrivateKey`,
  `*rsa.PrivateKey`, `*ecdsa.PrivateKey` or an `OpaqueSigner`; any other
  `crypto.Signer` gets `ErrUnsupportedKeyType`. The `cryptosigner` package
  wraps a `crypto.Signer` as an `OpaqueSigner`, converting an ECDSA DER
  signature to RFC 7518's R‖S and passing Ed25519 the whole message. An AWS
  KMS signer, as ADR 0003 anticipates, would go through it.
- `JSONWebKey.Thumbprint` handles RSA, EC and Ed25519 keys, so pulsar's kid
  (an RFC 7638 thumbprint) works for every key type.

### go-oidc v3.21.0

- `Provider` reads `id_token_signing_alg_values_supported` and keeps only
  the values in `supportedAlgorithms` (`oidc.go`): RS256/384/512,
  ES256/384/512, PS256/384/512 and `EdDSA`. `Provider.Verifier` then
  accepts those, when `Config.SupportedSigningAlgs` is empty (`verify.go`,
  `newVerifier`). With neither set, it accepts RS256 only.
- `RemoteKeySet` skips a JWK whose `alg` is not one of those (`jwks.go`,
  `jwkJSON.UnmarshalJSON`), so a key published with `alg: Ed25519` is
  ignored.
- `IDToken.VerifyAccessToken` hashes `at_hash` with SHA-256 for RS256, ES256
  and PS256, and SHA-512 for `EdDSA`; any other `alg` is an error.

So, with discovery listing `["RS256", "ES256", "EdDSA"]`, go-oidc verifies
ES256 and EdDSA ID tokens with no change to the web app or the CLI. An
`Ed25519` ID token fails: the algorithm is dropped from discovery, the key
from the JWK Set, and go-jose cannot verify it. No go-oidc issue for
`Ed25519` was found.

### golang.org/x/oauth2 v0.38.0

The examples import only the root package, which exchanges codes and
refreshes tokens and verifies no JWT. The `jws` subpackage is not imported.

### What the examples would need

| Example                  | ES256 or EdDSA ID tokens                                                                                                                                                         | ES256 or EdDSA access tokens                                                                                    |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Web app, CLI             | No code change: go-oidc takes the algorithms from discovery. Setting `SupportedSigningAlgs` to the Client's registered algorithm would follow Core §3.1.3.7 step 6 more closely. | Not verified by these examples.                                                                                 |
| API                      | Not applicable.                                                                                                                                                                  | `jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})` and its README row change to the API's algorithm. |
| `examples_test.go`       | `keyID` parses with RS256 only.                                                                                                                                                  | The same.                                                                                                       |
| `examples/registry.json` | A Client registered for ES256 or EdDSA, so that the examples prove the path over the wire.                                                                                       | A Resource Server whose tokens use it, if the algorithm is chosen per Resource Server.                          |

## Key management

- **One key per algorithm.** Each key is used with exactly one algorithm
  (RFC 8725 §3.1), so the JWK Set holds one current RSA key, one P-256 key
  and, for EdDSA, one Ed25519 key, each with its `kid` and `alg`. Core §10.1
  already requires the `kid` in every header, which pulsar sends. Thumbprints
  of keys of different types differ, so kids stay unique.
- **Generation.** `crypto/ecdsa` P-256 and `crypto/ed25519` keys encode as
  PKCS #8 like RSA keys, so the sealing in ADR 0003 (AES-256-GCM under a key
  derived from `PULSAR_SECRET`, with the kid as additional data) is
  unchanged. `open` would check the decrypted key's type and curve against
  the row's algorithm, as it checks RSA size today.
- **Schema.** `signing_keys` needs an `alg` column. `reload` retires a key
  by its successor, today the next row; with several algorithms the successor
  is the next row of the same algorithm, and it must know the algorithm
  before decrypting, since retired keys are not decrypted. A new migration,
  00015, adds the column and sets it to `RS256` for existing rows, and
  `ListSigningKeys` orders by algorithm, then activation.
- **First start and new algorithms.** `ensureKey` generates the first key
  of each algorithm under the advisory lock. A key of an algorithm added to
  a database that already serves tokens needs `ActivationDelay` before it
  signs, as a rotated key does, so that every replica's JWK Set and every
  Client's cached copy has it first; only an empty database may sign at once.
- **Rotation.** `pulsar keys rotate` either rotates every algorithm at once,
  with one activation time, or takes the algorithm as an argument. `Rotated`
  reports one kid today.
- **Verification.** `verify` takes the key by `kid`, then requires the
  header's `alg` to be that key's algorithm (RFC 8725 §3.1). Hints signed by
  retired keys keep working per algorithm.
- **AWS KMS.** `ECC_NIST_P256` signs with `ECDSA_SHA_256`, which is ES256,
  and `ECC_NIST_EDWARDS25519` with `ED25519_SHA_512`, which "requires
  MessageType:RAW". `Sign` takes "Messages can be 0-4096 bytes", so an
  Ed25519 KMS key can sign a JWT whose signing input is at most 4096 bytes;
  RSA and ECDSA sign a digest and have no such limit. ECDSA signatures come
  back "DER-encoded", which go-jose's `cryptosigner` converts. RSA keys
  share 1,000 requests per second, and ECC keys, Ed25519 included, a separate
  1,000.

Sources: <https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html>,
<https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html>,
<https://docs.aws.amazon.com/kms/latest/developerguide/requests-per-second.html>.

## The conformance suite at release-v5.3.4

- **No plan pulsar runs exercises another algorithm.** The Basic plan's two
  ID token algorithm modules, `oidcc-idtoken-signature` ("requests an ID token
  without specifying an algorithm (which should default to RS256)") and
  `oidcc-idtoken-unsigned`, carry `@VariantNotApplicable(parameter =
ClientRegistration.class, values = { "static_client" })`
  (`openid/OIDCCBasicTestPlan.java`), and pulsar runs with `static_client`.
  Form Post Basic reuses those modules; Config OP and RP-Initiated Logout
  have none. The Dynamic OP plan, which pulsar does not run, tests RS256 and
  `none` only. The suite's conditions that add an ID token algorithm to a
  registration request cover RS256, PS256 and `none`
  (`condition/client/AddIdTokenSigningAlg*ToDynamicRegistrationRequest.java`).
- **Discovery.** `OIDCCCheckDiscEndpointIdTokenSigningAlgValuesSupported`
  requires `RS256` ("RS256 support is required, but the server does not list
  it") and does not penalize other values. The RFC 8414 schema the Config OP
  plan validates against has no `enum` for the field.
- **Verification.** `AbstractVerifyJwsSignature` selects the key by `kid`,
  then by `kty`, and verifies OKP Ed25519 keys with Nimbus's `Ed25519Verifier`,
  which accepts `EdDSA` and `Ed25519`. `JWAUtil.getDigestAlgorithmForSigAlg`
  hashes `at_hash` with SHA-512 for `EdDSA` and `Ed25519`. The suite pins
  `nimbus-jose-jwt` 10.9 (`pom.xml`), which defines `JWSAlgorithm.Ed25519`.
- **JWK Set.** `CheckForKeyIdInServerJWKs` and
  `CheckDistinctKeyIdValueInServerJWKs` fail a key without a `kid` or two
  keys sharing one; `WarnOnUnusableJwksKeys` warns on an unknown `alg`, and
  `ES256`, `EdDSA` and `Ed25519` are known.

So publishing an ES256 and an EdDSA key beside the RSA key, while the
conformance Clients stay on RS256, should change no result. That is read from
code; no run was made.

## Size

### What changes

| Area                                                     | Change                                                                                                                                                                                                                                                                                                         |
| -------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `internal/signing`                                       | Keys of several types; per-algorithm active key, successor and retention; generation and `open` per type; JWK Set with one key per algorithm; `SignJWT` takes the algorithm; `verify` checks the header's `alg` against the key's.                                                                             |
| `internal/postgres/migrations`, `queries.sql`            | 00015 adds `alg`; listing and the existence check per algorithm.                                                                                                                                                                                                                                               |
| `cmd/pulsar`                                             | `keys rotate` rotates each algorithm, and logs each kid.                                                                                                                                                                                                                                                       |
| `internal/registry`                                      | `id_token_signed_response_alg` on Clients, checked against the supported list; RS256 when absent. Optionally an algorithm on Resource Servers.                                                                                                                                                                 |
| `internal/oidc/token.go`                                 | The ID token's algorithm from the Client; `at_hash` by algorithm (SHA-512 for EdDSA); the access token's algorithm.                                                                                                                                                                                            |
| `internal/oidc/authorize.go`, `logout.go`, `userinfo.go` | Hints and access tokens parse with every supported algorithm, not RS256 alone.                                                                                                                                                                                                                                 |
| `internal/oidc/discovery.go`                             | `id_token_signing_alg_values_supported` lists every supported algorithm.                                                                                                                                                                                                                                       |
| `docs/requirements/`                                     | New clauses: RFC 7518 §3.4 and its EC JWK members (§6.2.1); RFC 8037 §3.1 and the OKP members (§2); Registration §2 `id_token_signed_response_alg`; the Token Hash guide's §2. Notes that name RS256 change in REQ-DISC-9, REQ-CORE-7, REQ-AT-9, REQ-LOGOUT-2, REQ-JWTBCP-1, and the RFC 7518 file's preamble. |
| `docs/adr/`                                              | ADR 0003 decides "an RSA-2048 key for RS256"; it needs amending, or a new ADR that supersedes that part.                                                                                                                                                                                                       |
| `examples/`                                              | The API's allow-list and README; `keyID` in the tests; a Client, and perhaps a Resource Server, on ES256 or EdDSA in `registry.json`.                                                                                                                                                                          |
| `README.md`, `conformance/README.md`                     | Sentences that say pulsar's tokens are RS256.                                                                                                                                                                                                                                                                  |

### Tickets

1. **Signing keys of several algorithms.** `internal/signing`, the
   migration, `keys rotate`, the JWK Set, verification of every algorithm;
   tokens still RS256. The ADR change. Closest to #23, key rotation (PR #45,
   +679/−124, 13 files), and #81 (PR #82, +423/−70, 12 files).
2. **ID token algorithm per Client.** Registry field, token signing,
   `at_hash`, discovery, requirements, and the examples' Client and test.
3. **Access token algorithm** (optional), per Resource Server, and the API
   example's allow-list.

For scale, #69's three sub-issues closed with PRs of +840, +2,099 and
+1,313 lines, and #70's with +1,375, +1,962 and +1,662. The tickets above
look closer to #72 (Form Post, +840) each than to #73 (RP-Initiated Logout,
+2,099); in total, roughly one of those specs' larger sub-issues, or a third
to a half of either spec. That is an estimate from the areas listed, not a
measurement.

## Recommendations

- Keep RS256 the default for every Client and every token, and keep it in
  discovery (Core §15.1, Discovery §3, Registration §2, RFC 9068 §2.1). The
  conformance plans need nothing else.
- Add ES256 first. It is fully specified in JOSE (RFC 9864 §2.1),
  "Recommended+" in RFC 7518, signed by all five open-source providers,
  verified by go-oidc from discovery, and backed by AWS KMS without a
  message-size limit.
- Let each Client choose its ID token algorithm with
  `id_token_signed_response_alg`, RS256 when absent, as Registration §2 and
  Core §3.1.3.7 describe and node-oidc-provider, Keycloak and Spring do.
- For access tokens, either stay with RS256 or let each Resource Server
  choose, as node-oidc-provider does; RFC 9068 offers no negotiation, and the
  registry already lists Resource Servers. Access tokens for UserInfo stay
  RS256, since pulsar verifies those itself.
- Publish one key per supported algorithm at all times, each with `kid` and
  `alg`, and rotate them together. RFC 9068 §5's point, that a Resource
  Server accepts any published key, argues for publishing only algorithms
  pulsar offers.
- If EdDSA is added, publish `EdDSA`, not `Ed25519`, and record the
  departure from RFC 9864 §4.4's SHOULD beside its requirement. go-jose
  v4.1.9 can neither sign nor verify `Ed25519` (go-jose/go-jose#330, open),
  and go-oidc v3.21.0 drops it from discovery and skips keys that name it, so
  neither pulsar nor its examples could use it; that is the "documented
  operational" requirement §4.4 allows. Keycloak, Hydra and Zitadel publish
  `EdDSA` too. Hash `at_hash` with SHA-512, as the Token Hash guide, the
  conformance suite, go-oidc, Keycloak, Zitadel and node-oidc-provider do.
  Revisit when go-jose supports `Ed25519`.
- Amend ADR 0003, or write one that supersedes its "RSA-2048 key for RS256"
  decision, before the code.

## Decision

The maintainer decided on 2026-11-10 to add neither algorithm for now,
departing from the recommendation above to add ES256:

- ES256: OpenID Connect Core §15.1 and RFC 9068 §2.1 require only RS256,
  and no consumer needs another; the work, a third to a half of a
  specification, changes key storage and rotation for no current user.
- EdDSA: the same, and it could only be published under the name RFC 9864
  deprecates, since go-jose can neither sign nor verify `Ed25519`.

AGENTS.md's "Deliberately not doing" records it.
