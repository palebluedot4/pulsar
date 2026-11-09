# Client assertions name the issuer as their sole audience

pulsar accepts a `private_key_jwt` assertion only if its `aud` holds
pulsar's issuer identifier and nothing else, as a string or as an array
of one, compared as strings, as RFC 10070 §4 requires. An assertion whose
`aud` is the token endpoint URL, or an array that holds the issuer beside
another value, gets `invalid_client`. Until this decision, pulsar accepted
the token endpoint URL or the issuer anywhere in `aud`, which let a
malicious authorization server replay at pulsar an assertion a Client had
signed for it (CVE-2025-27370, CVE-2025-27371). The evidence is in
[docs/research/client-assertion-audience.md](../research/client-assertion-audience.md).

## Considered options

- **Keep accepting the token endpoint URL**, as OpenID Connect Core 1.0
  §9 still tells Clients to send it, and as Spring Authorization Server
  and Ory Hydra do: RFC 10070 §4 says the authorization server "MUST
  reject" it, and the attack works through it.
- **A setting to accept it again**, as Keycloak and Duende offer: pulsar
  is not deployed, so no Client depends on the old rule, and a setting
  that brings an attack back is one an operator can turn on by mistake.
- **The issuer as a string only**, as FAPI 2.0 and the unapproved errata
  set 3 of OpenID Connect Core 1.0 require: RFC 10070, the only one of
  them in scope, does not restrict the type, and its authors dropped that
  restriction on purpose (draft-ietf-oauth-rfc7523bis-11, document
  history of -03). An array of
  one names no other audience, so refusing it would refuse Clients that
  meet RFC 10070 for no gain against the attack.
- **Requiring `typ` to be `client-authentication+jwt`**: RFC 10070 §4
  calls rejecting an untyped assertion "NOT RECOMMENDED", since typing
  alone does not stop the attack. pulsar does not read `typ`.

## Consequences

- A Client that follows OpenID Connect Core 1.0 §9's SHOULD, and sends
  the token endpoint URL, cannot authenticate. That is a departure from
  §9 that RFC 10070 §6 anticipates: "some clients implementing earlier
  versions may not interoperate with authorization servers that strictly
  enforce the updated requirements". A Client that sends the issuer
  instead authenticates at pulsar, but not at a server, such as Ory
  Hydra, that accepts only its token endpoint URL.
- The OpenID conformance suite sends the token endpoint URL in its
  OpenID Connect plans that use `private_key_jwt`. The Basic OP and
  Config OP plans, which pulsar runs, use none, so their results do not
  change; in the Dynamic OP plan, which pulsar does not run, those
  assertions would be refused.
- When the OpenID Foundation publishes errata set 3, or Connect 1.1, this
  decision is to be checked against it, in particular whether an array
  of one is still refused there.
- Discovery is unchanged: RFC 10070 defines no metadata, and
  `token_endpoint_auth_methods_supported` still lists `private_key_jwt`.
