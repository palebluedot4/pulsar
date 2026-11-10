# The API example

A Resource Server: an API that accepts the access tokens pulsar issues for
it, and verifies each one itself, with no call to pulsar but for its
discovery document and JWK Set. Its routes keep each End-User's notes, by
their `sub`:

| Route         | Scope it needs |
| ------------- | -------------- |
| `GET /notes`  | `notes:read`   |
| `POST /notes` | `notes:write`  |

[`api.go`](api.go) is the code; [`cmd/api`](../cmd/api/main.go) serves it.

## What it checks, and why

RFC 9068 §4 lists what a Resource Server must check of a JWT access token.
`Verify` makes each check in turn, and any failure refuses the token:

| Check                                                  | Why                                                                                                                                                                                                                            | Clause                               |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------ |
| `alg` is `RS256`                                       | The verifier, not the token, chooses the algorithm, and `none` is refused. RS256 is the algorithm RFC 9068 requires both sides to support, and the one pulsar signs with                                                       | RFC 9068 §2.1, §4; RFC 8725 §3.1     |
| `typ` is `at+jwt`, in any case                         | So that another JWT pulsar signed with the same key, such as an ID token, is not taken for an access token                                                                                                                     | RFC 9068 §4; RFC 8725 §3.11          |
| The signature, by a key in pulsar's JWK Set            | Only pulsar's keys, found from the `jwks_uri` of pulsar's discovery document, whose `issuer` must be the one configured                                                                                                        | RFC 9068 §4; OIDC Discovery §4.3     |
| `iss` is pulsar's issuer, exactly                      | A token from another authorization server is refused                                                                                                                                                                           | RFC 9068 §4                          |
| `aud` names the API's identifier                       | A token pulsar issued for something else, such as its own UserInfo, is refused: a token stolen from another recipient cannot be replayed here. pulsar puts the identifier in `aud` when the Client asks for it with `resource` | RFC 9068 §4; RFC 9700 §2.3; RFC 8707 |
| The current time is before `exp`, and `exp` is present | An expired token is refused; pulsar's access tokens live ten minutes                                                                                                                                                           | RFC 9068 §2.2, §4                    |
| `scope` holds the scope the route needs                | A token is used only for what the End-User allowed                                                                                                                                                                             | RFC 9068 §2.2.3; RFC 6750 §3.1       |

It answers as RFC 6750 §3 says, with a `WWW-Authenticate` challenge of the
Bearer scheme:

| Request                                    | Status | `WWW-Authenticate`                                                                |
| ------------------------------------------ | ------ | --------------------------------------------------------------------------------- |
| No token, or credentials of another scheme | 401    | `Bearer`, with no error code (§3.1)                                               |
| A token that fails any check above         | 401    | `Bearer error="invalid_token", error_description="The access token is invalid."`  |
| A valid token without the route's scope    | 403    | `Bearer error="insufficient_scope", scope="notes:write"`, naming the scope needed |

The reason a token failed is not sent to the Client.

It accepts the token in the `Authorization` header, the one method RFC 6750
§2.1 requires a Resource Server to support, by a scheme name compared
without regard to case (RFC 9110 §11.1).

## The JWK Set

The API fetches pulsar's JWK Set when it first needs it, and caches it,
through go-oidc's `RemoteKeySet`. When a token is signed with a key the
cache does not hold, as after `pulsar keys rotate`, it fetches the set again,
as OpenID Connect Core 1.0 §10.1.1 describes: "The verifier knows to go back
to the jwks_uri location to re-retrieve the keys when it sees an unfamiliar
kid value." Requests waiting on the same fetch share it. pulsar publishes a
new key two minutes before it signs with it, and keeps the old one in its JWK
Set until every token it signed has expired, so a rotation refuses no valid
token.

`RemoteKeySet` fetches the set again on any token the cached keys do not
verify, not only one with an unfamiliar `kid`: a forged token with a known
`kid` also makes it fetch. Nothing limits how often it fetches, so a
Resource Server in production would rate-limit those fetches, or refresh
the set on a schedule.

## What it does not do

- It does not learn that pulsar revoked a token: it accepts one until its
  `exp`, at most ten minutes later. Introspection (RFC 7662), which would
  tell it, is one of the things pulsar does not do.
- It checks no claim beyond those above: not `nbf`, `iat`, `client_id` or
  `jti`.
- It accepts no token in a form body or in the query (RFC 6750 §2.2, §2.3).
- It keeps notes in memory, for as long as it runs, without limit, and
  serves plain http.
