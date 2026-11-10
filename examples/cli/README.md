# The CLI example

A native app: a public Client, with no secret, that signs the End-User in
through their own browser and a redirect to the loopback interface, as
RFC 8252 describes. It then calls the API example with the access token it
gets for it.

```sh
cli list         # signs in for notes:read, and lists the End-User's notes
cli add TEXT     # signs in for notes:write, and adds a note
```

[`cli.go`](cli.go) is the code; [`cmd/cli`](../cmd/cli/main.go) runs it.
Each run signs in again and asks only for the scope its command needs.

## What it does, and why

| Step                                                                                                                             | Why                                                                                                                                                                                              | Clause                                      |
| -------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------- |
| Opens the authorization request in the system browser                                                                            | The End-User types their password into pulsar's page in their own browser, never into the app                                                                                                    | RFC 8252 §8.12                              |
| Listens on `127.0.0.1`, on a port the operating system chooses, and sends `http://127.0.0.1:{port}/callback` as its redirect URI | The redirect comes back to the app alone. The IP literal, not `localhost`, so the app listens on no other interface. pulsar accepts any port for the redirect URI the CLI registered without one | RFC 8252 §7.3, §8.3                         |
| Sends a PKCE `code_challenge` by `S256`, and the `code_verifier` with the code                                                   | A public Client cannot authenticate, so the verifier proves that the app that redeems the code is the one that asked for it                                                                      | RFC 8252 §8.1; RFC 9700 §2.1.1; RFC 7636 §4 |
| Sends a random `state`, and ignores a response without it                                                                        | Another page cannot make the app redeem a code it did not ask for                                                                                                                                | RFC 6749 §10.12                             |
| Requires `iss` in the response to be pulsar's issuer                                                                             | pulsar's discovery document says it sends `iss`, so a response without it, or from another authorization server, is refused                                                                      | RFC 9207 §2.4                               |
| Sends its `client_id` in the token request's body, and no secret                                                                 | It is a public Client: it has no credentials, and pulsar refuses one that sends them                                                                                                             | RFC 6749 §2.1, §3.2.1                       |
| Sends `resource`, the API's identifier, at both endpoints                                                                        | The access token is then for the API: its `aud` is the API's identifier, and its `scope` holds only the API's scopes                                                                             | RFC 8707 §2.1, §2.2                         |
| Verifies the ID token: its signature against pulsar's JWK Set, `iss`, `aud`, `exp`, and the `nonce` it sent                      | The End-User the app reports is the one pulsar signed in for this request                                                                                                                        | OpenID Connect Core 1.0 §3.1.2.1, §3.1.3.7  |
| Calls the API with the access token in the `Authorization` header                                                                | The method every Resource Server must support                                                                                                                                                    | RFC 6750 §2.1                               |

Without `resource`, the access token is for pulsar's UserInfo, and the API
refuses it.

## What it does not do

- It keeps no token: it asks for no refresh token, and signs in on every
  run.
- It does not sign the End-User out of pulsar.
