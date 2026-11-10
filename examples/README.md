# Examples

Consumers of pulsar, in a Go module of their own that does not require
pulsar's. They reach pulsar only over the network, and use only
[`golang.org/x/oauth2`](https://pkg.go.dev/golang.org/x/oauth2),
[`github.com/coreos/go-oidc`](https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc)
and [`github.com/go-jose/go-jose`](https://pkg.go.dev/github.com/go-jose/go-jose/v4)
beside the standard library. Each takes pulsar's issuer and its own
registration from flags or the environment, and discovers everything else
from pulsar's discovery document.

| Program     | Package                       | Command                             | What it is                                                                                                                                                                                                                 |
| ----------- | ----------------------------- | ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The web app | [`webapp/`](webapp/README.md) | [`cmd/webapp/`](cmd/webapp/main.go) | A confidential Client on the server, a backend-for-frontend, that keeps the End-User's tokens from the browser, calls the API, refreshes its access token, and at logout revokes its refresh token and signs out of pulsar |
| The API     | [`api/`](api/README.md)       | [`cmd/api/`](cmd/api/main.go)       | A Resource Server that verifies each access token itself against pulsar's JWK Set, and keeps each End-User's notes                                                                                                         |
| The CLI     | [`cli/`](cli/README.md)       | [`cmd/cli/`](cmd/cli/main.go)       | A public Client that signs the End-User in through their browser and a loopback redirect, gets an access token for the API, and calls it                                                                                   |

Each package's README says what it checks and why, citing the clause each
check comes from.

| File               | Contents                                                                                                                                                                                                                                    |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `registry.json`    | pulsar's registry for the examples: the web app's Client `webapp`, with its redirect URIs under `http://localhost:8082`; the CLI's Client `cli`; the API's Resource Server `https://api.example/notes` with its two scopes; and an End-User |
| `compose.yaml`     | pulsar and its PostgreSQL, as `make examples` runs them, with pulsar on the host's loopback interface at `http://127.0.0.1:9080`                                                                                                            |
| `examples_test.go` | The tests of the CLI and the API, and the browser the tests act as                                                                                                                                                                          |
| `webapp_test.go`   | The test of the web app, which it serves at `localhost:8082`, with the API                                                                                                                                                                  |

The End-User's username is `example` and their password `examples-password`.
The web app's client secret is `fXVx4UH6F0awyDIESJsM21sLdOr_SDTYmQfHerTUPPY`.
Like the conformance suite's credentials, they are published deliberately,
for this stack only ([SECURITY.md](../SECURITY.md)).

## Running the tests

With Docker (and Compose v2), openssl and Go installed, from the
repository's root:

```sh
make examples
```

This starts pulsar in Docker Compose with `registry.json`, and runs the
tests in `examples_test.go` and `webapp_test.go` against it. They reach
pulsar only by its URL. They act as the End-User's browser with Go's HTTP
client and a cookie jar: they follow pulsar's redirects, sign in on its
login page, allow the request on its consent page, and confirm on its
logout page. CI runs the same target on every pull request. The run takes a
few minutes, since a key that `pulsar keys rotate` stores signs only two
minutes later. The web app's test serves it at `localhost:8082`, so that
port must be free.

## What the tests prove

Over the wire, with `x/oauth2` and `go-oidc` on the other side:

- The web app signs in with PKCE, `state`, `nonce`, `offline_access` and
  `resource`, authenticating with its secret; refuses a response to its
  callback with another `state`; verifies the ID token; and adds and lists
  a note through the API. When its access token has expired
  by its clock, which the test moves forward rather than wait ten minutes,
  it refreshes it, and the API accepts the new one; twice, so the second
  refresh uses the refresh token the first returned. Its logout revokes its
  refresh token, and sends the browser to pulsar's logout endpoint with the
  ID token as `id_token_hint`, its `post_logout_redirect_uri` and a
  `state`. A return with another `state` is refused. The End-User confirms
  on pulsar's page, and pulsar sends them back with the `state`. Then the
  web app's last refresh token, which it never redeemed, gets
  `invalid_grant`, and an authorization request with `prompt=none` in the
  same browser gets `login_required`.
- Of every response the browser receives in that test, none holds an
  access or refresh token, and only two hold the ID token: the web app's
  redirect to pulsar's logout endpoint, as `id_token_hint`, and pulsar's
  logout page, which carries it in its form. After sign-in, the browser
  holds one cookie for the web app.
- The CLI signs in through a loopback redirect on a port the operating
  system chose, with PKCE, `state` and `nonce`, and `resource` at both
  endpoints; it verifies the ID token; and it calls the API with its access
  token, which the API accepts.
- The API refuses, with 401 and a Bearer challenge: no token; a token of
  another scheme; a token pulsar issued for its own UserInfo; a token at its
  `exp`, by the API's clock, which the test sets to that time rather than
  wait ten minutes; a token whose claims were changed; one with `alg` `none`; and an ID
  token. It refuses a valid token without the route's scope with 403 and
  `insufficient_scope`. It answers 503, not `invalid_token`, when it cannot
  reach pulsar's JWK Set to check a token.
- After `pulsar keys rotate`, once pulsar signs with the new key, the API,
  which cached pulsar's JWK Set before, accepts a token signed with the new
  key, and still accepts one the old key signed.

They do not prove:

- That a browser works: no browser runs. Go's cookie jar keeps pulsar's
  cookies and the web app's as a browser does, but ignores `SameSite`, so
  the tests do not show which requests a browser would send the web app's
  cookies on. Nothing runs JavaScript or follows the web app's page
  refresh, which the test replaces with a request of its own, and the
  commands in `cmd/` are not run.
- Anything about TLS: pulsar's issuer is `http` on a loopback host.
- That the API refuses a revoked token: it cannot see that a token was
  revoked, and accepts it until it expires, at most ten minutes later.
- That the web app refuses a wrong `iss` or an ID token that fails
  verification, or ends its session when a refresh is refused: no test
  makes pulsar send it one.
- That the examples are fit for production. They keep notes, and the web
  app its sessions, in memory; [the API's
  README](api/README.md#what-it-does-not-do) and [the web app's
  README](webapp/README.md#what-it-does-not-do) list what they leave out.

## Running them by hand

Start pulsar with this registry, as the main README describes, with
`PULSAR_ISSUER=http://localhost:8080` and
`PULSAR_REGISTRY=examples/registry.json`: a browser keeps pulsar's `Secure`
Login Session cookie over plain http only on `localhost`, and the web app's
`Secure` cookies likewise. Then, from this directory:

```sh
export ISSUER=http://localhost:8080 API_IDENTIFIER=https://api.example/notes
go run ./cmd/api &                # serves on 127.0.0.1:8081
go run ./cmd/cli add 'buy milk'   # opens a browser to sign in as example
go run ./cmd/cli list
WEBAPP_CLIENT_SECRET=fXVx4UH6F0awyDIESJsM21sLdOr_SDTYmQfHerTUPPY \
  go run ./cmd/webapp &           # serves on localhost:8082
```

Then open `http://localhost:8082` in a browser, and sign in as `example`.
