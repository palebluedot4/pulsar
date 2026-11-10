# Examples

Consumers of pulsar, in a Go module of their own that does not require
pulsar's. They reach pulsar only over the network, and use only
[`golang.org/x/oauth2`](https://pkg.go.dev/golang.org/x/oauth2),
[`github.com/coreos/go-oidc`](https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc)
and [`github.com/go-jose/go-jose`](https://pkg.go.dev/github.com/go-jose/go-jose/v4)
beside the standard library. Each takes pulsar's issuer and its own
registration from flags or the environment, and discovers everything else
from pulsar's discovery document.

| Program | Package                 | Command                       | What it is                                                                                                                               |
| ------- | ----------------------- | ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| The API | [`api/`](api/README.md) | [`cmd/api/`](cmd/api/main.go) | A Resource Server that verifies each access token itself against pulsar's JWK Set, and keeps each End-User's notes                       |
| The CLI | [`cli/`](cli/README.md) | [`cmd/cli/`](cmd/cli/main.go) | A public Client that signs the End-User in through their browser and a loopback redirect, gets an access token for the API, and calls it |

Each package's README says what it checks and why, citing the clause each
check comes from.

| File               | Contents                                                                                                                                               |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `registry.json`    | pulsar's registry for the examples: the CLI's Client `cli`, the API's Resource Server `https://api.example/notes` with its two scopes, and an End-User |
| `compose.yaml`     | pulsar and its PostgreSQL, as `make examples` runs them, with pulsar on the host's loopback interface at `http://127.0.0.1:9080`                       |
| `examples_test.go` | The tests: they run the CLI and the API against that pulsar, acting as the End-User's browser                                                          |

The End-User's username is `example` and their password `examples-password`.
Like the conformance suite's credentials, it is published deliberately, for
this stack only ([SECURITY.md](../SECURITY.md)).

## Running the tests

With Docker (and Compose v2), openssl and Go installed, from the
repository's root:

```sh
make examples
```

This starts pulsar in Docker Compose with `registry.json`, and runs the
tests in `examples_test.go` against it. They reach pulsar only by its URL.
They act as the End-User's browser with Go's HTTP client and a cookie jar:
they follow pulsar's redirects, sign in on its login page, and allow the
request on its consent page. CI runs the same target on every pull request.
The run takes a few minutes, since a key that `pulsar keys rotate` stores
signs only two minutes later.

## What the tests prove

Over the wire, with `x/oauth2` and `go-oidc` on the other side:

- The CLI signs in through a loopback redirect on a port the operating
  system chose, with PKCE, `state` and `nonce`, and `resource` at both
  endpoints; it verifies the ID token; and it calls the API with its access
  token, which the API accepts.
- The API refuses, with 401 and a Bearer challenge: no token; a token of
  another scheme; a token pulsar issued for its own UserInfo; a token at its
  `exp`; a token whose claims were changed; one with `alg` `none`; and an ID
  token. It refuses a valid token without the route's scope with 403 and
  `insufficient_scope`.
- After `pulsar keys rotate`, once pulsar signs with the new key, the API,
  which cached pulsar's JWK Set before, accepts a token signed with the new
  key, and still accepts one the old key signed.

They do not prove:

- That a browser works: no browser runs. Go's cookie jar keeps pulsar's
  cookies as a browser does, but nothing runs JavaScript, and the commands in
  `cmd/` that open a real browser are not run.
- Anything about TLS: pulsar's issuer is `http` on a loopback host.
- Refresh, logout or revocation: the web app example (#77) is to show
  those. The API cannot see that a token was revoked; it accepts it until it
  expires, at most ten minutes later.
- That the examples are fit for production. They keep notes in memory, and
  [the API's README](api/README.md#what-it-does-not-do) lists what it leaves
  out.

## Running them by hand

Start pulsar with this registry, as the main README describes, with
`PULSAR_ISSUER=http://localhost:8080` and
`PULSAR_REGISTRY=examples/registry.json`: a browser keeps pulsar's `Secure`
Login Session cookie over plain http only on `localhost`. Then, from this
directory:

```sh
export ISSUER=http://localhost:8080 API_IDENTIFIER=https://api.example/notes
go run ./cmd/api &                # serves on 127.0.0.1:8081
go run ./cmd/cli add 'buy milk'   # opens a browser to sign in as example
go run ./cmd/cli list
```
