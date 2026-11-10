# Machine Clients are their own Subject

A machine Client is one registered for the client credentials grant
alone: it calls a Resource Server on its own behalf, with no End-User. The
`sub` of its access tokens is its `client_id`, as RFC 9068 §2.2 says it
SHOULD be for this grant, so the tokens' `sub` and `client_id` claims are
equal. End-User Subjects are always lowercase UUIDs (REQ-CORE-1), and
pulsar refuses to start on a machine Client whose `client_id` has that
form, so a machine Client's `sub` can never equal an End-User's, as
RFC 9700 §4.15.1 and RFC 9068 §5 ask. A Client lists `client_credentials`
alone, as RFC 7591 §5 allows, so it acts either for End-Users or for
itself, never both, and a Resource Server tells which by `sub`. The evidence
is in [docs/research/client-credentials.md](../research/client-credentials.md).

## Considered options

- **A user record for each machine Client**, as Keycloak and Zitadel give
  a service account a user whose identifier, a UUID like any other user's,
  is its `sub`: pulsar's End-Users are people who sign in at the login
  page, with a password and claims, and a machine Client is neither. One
  namespace would keep the two from colliding, but a Resource Server could
  then not tell from `sub` whether a person or a program is calling.
- **The `client_id` with a suffix**, as Auth0 sends `<client_id>@clients`:
  the form check above keeps the two apart without changing the value RFC
  9068 §2.2 suggests, and a suffix is a convention no specification names.
- **No check of the `client_id`**, as node-oidc-provider, Ory Hydra and
  Spring Authorization Server, which use the `client_id` as `sub`, have
  none: Clients there may choose their `client_id` through Dynamic Client
  Registration. pulsar's operator chooses it
  ([ADR 0001](0001-clients-and-end-users-from-a-static-file.md)), but a
  mistake would let a Client be mistaken for an End-User, and the check
  costs nothing.
- **One Client for both kinds of grant**, as Keycloak, Hydra and Auth0
  allow: its access tokens would carry its `client_id` as `sub` for one
  grant and an End-User's for the other, and the registry could not keep
  the scopes it may take for itself apart from those End-Users consent to.

## Consequences

- A Resource Server that relies on `sub` sees a machine Client's
  `client_id` there, and the same value in `client_id`. Changing that
  later breaks every Resource Server that relies on it, which is why this
  is recorded.
- A `client_id` that is a UUID in another form, such as uppercase, is
  allowed: Subjects are compared as case-sensitive strings (OpenID Connect
  Core 1.0 §2), so it cannot equal one. A Resource Server that compares
  `sub` without regard to case could confuse the two; it should not.
- A program that needs to act both for End-Users and for itself is
  registered as two Clients.
- UserInfo refuses a machine Client's access token, since its `aud` is a
  Resource Server's (REQ-AT-8), so no End-User is looked up by its `sub`.
