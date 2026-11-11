# Configuration

pulsar reads its configuration from the environment, and the Clients,
End-Users and Resource Servers it knows from a registry file. It refuses to
start if either is invalid.

## Environment

| Variable              | Required      | Meaning                                                                                                                                                                                            |
| --------------------- | ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PULSAR_ISSUER`       | Yes           | The Issuer Identifier: an `https` URL, or `http` on a loopback host, with no query, fragment or trailing slash, in canonical form (OpenID Connect Discovery 1.0 §3)                                |
| `PULSAR_DATABASE_URL` | Yes           | A PostgreSQL connection string, as a URL or in keyword/value form, for a database that already exists                                                                                              |
| `PULSAR_SECRET`       | Yes           | 32 random bytes in standard, padded base64, as `openssl rand -base64 32` prints, from which the key that encrypts the signing keys is derived. Every start against a database needs the same value |
| `PULSAR_REGISTRY`     | Yes           | The path of the registry file                                                                                                                                                                      |
| `PULSAR_ADDR`         | No; `:8080`   | The TCP address to listen on                                                                                                                                                                       |
| `PULSAR_TLS_CERT`     | With the key  | A PEM certificate chain, to serve TLS without a proxy. `PULSAR_ISSUER` must then be `https`                                                                                                        |
| `PULSAR_TLS_KEY`      | With the cert | The certificate's PEM private key                                                                                                                                                                  |

What `PULSAR_DATABASE_URL` leaves out, pgx takes, as libpq does, from the
`PG*` environment variables it supports (`PGHOST`, `PGUSER`, `PGPASSWORD`,
`PGSSLMODE` and others), from the service file `PGSERVICE` names, and a
password from the password file.

With another `PULSAR_SECRET`, pulsar cannot decrypt its keys, so it never
becomes ready: it answers `/livez` until it has tried, and then exits with
an error ([ADR 0003](adr/0003-signing-keys-generated-and-stored-encrypted.md)).

## The registry

Resource Servers, Clients and End-Users are listed in a JSON document, read
at startup. The comment of
[internal/registry](../internal/registry/registry.go) describes its form;
[conformance/registry.json](../conformance/registry.json) and
[examples/registry.json](../examples/registry.json) are examples
([ADR 0001](adr/0001-clients-and-end-users-from-a-static-file.md)).

- Client secrets and passwords appear in it only as Argon2id hashes in the
  PHC string format; [operations.md](operations.md) says how to make them.
- A Resource Server is registered by its identifier, an absolute URI
  without a fragment that is not the issuer, with at least one scope, each
  with a description. None of its scopes may be one of OpenID Connect's or
  another Resource Server's.
- Each Client lists the Resource Servers it may request.
- A Client acts for End-Users, through the authorization code flow, unless
  its `grant_types` lists `client_credentials` alone. It is then a machine
  Client, which acts for itself.
- A machine Client is confidential and registers no redirect URIs. It lists
  in `scope` the scopes it may be granted, each of a Resource Server it may
  request; with no End-User to consent, the registry is what authorizes
  them.
- A machine Client's `client_id` is the `sub` of its access tokens, so no
  Client's `client_id` may be a UUID, the form of every End-User's Subject
  ([ADR 0007](adr/0007-a-machine-clients-sub-is-its-client-id.md)).
- Register a machine Client for `private_key_jwt`, as RFC 9700 §2.5
  recommends asymmetric client authentication: the private key never leaves
  the Client, no secret is shared with pulsar or sent in a request, and
  each assertion is accepted once.

How pulsar treats tokens when an entry is removed is in
[behavior.md](behavior.md#registry-changes).
