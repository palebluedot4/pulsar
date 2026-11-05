# Signing keys: how OpenID Providers source, store and rotate them

Surveyed 2026-11-05 from source code and official documentation at Keycloak
26.8.1, Ory Hydra v26.2.0, Dex v2.46.1, Zitadel v4.20.1, Authelia v4.39.28,
node `oidc-provider` v9.13.3 and `luikyv/go-oidc` v0.25.0. Anything not
confirmed is marked **UNVERIFIED**.

## What providers do

| Product            | Where the private key lives                                                                                                                                 | Generated automatically                   | Rotation                                                                                                               | External signer                               |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| Keycloak           | Database, PEM in the key provider's config; no application-level encryption found. A `java-keystore` provider can load the key from a keystore file instead | Yes, on realm creation                    | Manual: a higher-priority provider; the old one becomes passive. Guide suggests 3–6 months                             | None in core docs (UNVERIFIED for extensions) |
| Ory Hydra          | Database, AES-256-GCM with `secrets.system`                                                                                                                 | Yes, on first use (`jwk/helper.go`)       | Manual (`hydra create jwks`); newest key signs; old keys stay until deleted                                            | PKCS#11 HSM                                   |
| Dex                | Storage backend, plaintext JSON                                                                                                                             | Yes, at start                             | Automatic, every 6h by default; old public keys kept for ID token validity (24h); replicas coordinate in a transaction | Vault/OpenBao transit                         |
| Zitadel            | Event store, encrypted with an application AES key (mode UNVERIFIED)                                                                                        | Yes                                       | Manual through the API; deactivated public keys stay until deleted                                                     | None documented                               |
| Authelia           | PEM files named in configuration                                                                                                                            | No                                        | Manual: edit the list                                                                                                  | None                                          |
| node oidc-provider | Whatever the host application passes as `jwks`                                                                                                              | Development keystore only, with a warning | Manual, two steps: append and reload, then move to the front                                                           | `features.externalSigningSupport`             |
| luikyv/go-oidc     | A `JWKSFunc` from the host application                                                                                                                      | No                                        | Up to the host                                                                                                         | `provider.WithSigner` (`crypto.Signer`)       |

Sources: Keycloak `AbstractGeneratedRsaKeyProviderFactory.java` and the
Server Administration Guide, "Managing realm keys"; Hydra
`.schema/config.schema.json`, `jwk/helper.go`,
<https://www.ory.com/docs/hydra/jwks>; Dex `storage/sql/crud.go`,
`server/signer/rotation.go`, `cmd/dex/serve.go`,
<https://dexidp.io/docs/configuration/tokens/>; Zitadel
`internal/command/command.go`, `cmd/defaults.yaml`,
<https://zitadel.com/docs/guides/integrate/login/oidc/webkeys>;
Authelia's OpenID Connect provider configuration,
`identity_providers.oidc.jwks`; oidc-provider
`lib/helpers/initialize_keystore.js`, `docs/README.md`; luikyv/go-oidc
`provider.WithSigner` and `JWKSFunc`.

Managed services: Auth0 rotation is customer-initiated, with the next key
published first (<https://auth0.com/docs/get-started/tenant-settings/signing-keys>);
Okta rotates automatically four times a year
(<https://developer.okta.com/docs/concepts/key-rotation/>); Cognito publishes
no schedule (UNVERIFIED).

## Guidance

- OpenID Connect Core 1.0 §10.1.1: rotate by adding keys to the JWKS and
  signing with the new `kid`; the JWKS "SHOULD retain recently decommissioned
  signing keys for a reasonable period". §15.1 makes RS256 mandatory.
- RFC 8725 and RFC 9700 say nothing about storage or rotation beyond key
  entropy (RFC 8725 §3.5) and metadata easing rotation (RFC 9700 §2.6).
- NIST SP 800-57 Part 1 Rev. 5, Table 1: a private signature key's
  cryptoperiod is 1–3 years.
- OWASP Key Management Cheat Sheet: advises against storing keys in
  plaintext, and prefers a vault or HSM and automated rotation.
  <https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html>
- AWS KMS RSA keys support `RSASSA_PKCS1_V1_5_SHA_256`, which is RS256
  (<https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html>);
  RSA signing shares a default quota of 1,000 requests per second per account
  and Region (<https://docs.aws.amazon.com/kms/latest/developerguide/requests-per-second.html>).

## Conclusion

Keycloak, Hydra, Dex and Zitadel generate their keys by default and keep
them in their own storage; Hydra and Zitadel encrypt them with an
application secret, in line with OWASP's advice. Authelia, and Keycloak
optionally, load keys from files; the embedded libraries take keys from
their host. Libraries that support a KMS do so through a
`crypto.Signer`-style hook.
