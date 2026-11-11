# The worker example

A job: a machine Client, which calls the API example on its own behalf,
with no End-User. pulsar's registry lists it for the client credentials
grant alone, with `private_key_jwt`, the public key it signs with, and the
scopes it may get. Each run gets an access token for the API, records a
note there saying when it ran, and prints the worker's notes.

```sh
worker     # records "ran at <time>", and prints the worker's notes
```

[`worker.go`](worker.go) is the code; [`cmd/worker`](../cmd/worker/main.go)
runs it. Its private key is in [`worker-key.json`](../worker-key.json),
published for the examples' stack only.

## What it does, and why

| Step                                                                                                                                  | Why                                                                                                                                                                                                                                     | Clause                                                   |
| ------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| Gets its access token with `grant_type=client_credentials`, through `golang.org/x/oauth2/clientcredentials`                           | No End-User is present to sign in or consent; the Client asks for access to what it controls, under the registry's authorization                                                                                                        | RFC 6749 §4.4, §4.4.2                                    |
| Authenticates with `private_key_jwt`: sends a JWT signed with its private key as `client_assertion`, with its `client_assertion_type` | Asymmetric client authentication: the private key never leaves the worker, and pulsar holds only the public key, so no secret is shared or sent                                                                                         | RFC 9700 §2.5; RFC 7523 §2.2; OpenID Connect Core 1.0 §9 |
| Signs a new assertion for each token request, with a random `jti` and an `exp` a minute away                                          | pulsar accepts each assertion once, and refuses one whose `jti` it has seen before its `exp`                                                                                                                                            | RFC 7523 §3; OpenID Connect Core 1.0 §9                  |
| Names itself in the assertion's `iss` and `sub`, and pulsar's issuer as its sole `aud`, not the token endpoint's URL                  | An assertion for pulsar cannot be replayed at another authorization server, nor one made for another authorization server be replayed at pulsar ([ADR 0006](../../docs/adr/0006-client-assertions-name-the-issuer-as-sole-audience.md)) | RFC 7523 §3; RFC 10070 §4                                |
| Types the assertion with `typ` `client-authentication+jwt`                                                                            | It cannot be taken for a JWT of another kind                                                                                                                                                                                            | RFC 10070 §4                                             |
| Sends its `client_id` in the body beside the assertion, and no secret by HTTP Basic                                                   | The `client_id` may accompany the assertion. x/oauth2, left to guess, would first send an empty secret by HTTP Basic beside the assertion, which pulsar refuses as two methods at once, and only then try the body                      | RFC 7521 §4.2, §4.2.1                                    |
| Sends `resource`, the API's identifier, and `scope`, both the API's scopes                                                            | pulsar issues this grant's token for one Resource Server, with scopes the registry lists for the worker, and has no default for either. The token's `aud` is the API's identifier, so the API accepts it                                | RFC 8707 §2; RFC 6749 §3.3; RFC 9068 §3                  |
| Uses the token until it expires, then gets a new one with a new assertion                                                             | The grant issues no refresh token: the worker can authenticate again at any time                                                                                                                                                        | RFC 6749 §4.4.3                                          |
| Calls the API with the access token in the `Authorization` header                                                                     | The method every Resource Server must support                                                                                                                                                                                           | RFC 6750 §2.1                                            |

The access token's `sub` and `client_id` are both `worker` (RFC 9068
§2.2). The API keeps notes by `sub`, so the worker's are its own, apart
from every End-User's: pulsar refuses to start on a Client whose
`client_id` is a UUID, the form of every End-User's Subject, so the two
cannot be equal (RFC 9700 §4.15.1,
[ADR 0007](../../docs/adr/0007-a-machine-clients-sub-is-its-client-id.md)).

## What it does not do

- It does not read its access token, which is the API's to read.
- It keeps no token between runs: each run authenticates again.
- It holds its private key in a file, unencrypted. A job in production
  would get it from a secret store, or use a key that cannot be exported.
