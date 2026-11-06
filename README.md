# pulsar

An OpenID Connect Provider in Go, built by AI agents under a harness that has
to prove it helps. The provider is the artifact; the method is the subject.
It is a reference implementation, not for production use. So far it serves
liveness and readiness checks, its discovery document, its JWK Set, a login
page that starts a Login Session, a consent page that remembers the scopes
an End-User allows each Client, and the authorization code flow, with
`prompt` and `max_age`, to an ID token and access token for Clients that
authenticate with `client_secret_basic`, `client_secret_post` or
`private_key_jwt`. Public Clients with PKCE, and UserInfo, are next.

## Running it

pulsar keeps its state in PostgreSQL, in a database that must exist. It
serves at once and meanwhile applies its migrations and loads its signing
keys, generating the first one if the database holds none: `/readyz` and the
JWK Set answer 503 until both are done, and pulsar exits if either fails.
After that `/readyz` answers 200 while a ping through its connection pool
succeeds, and 503 when one fails.

The private keys are stored encrypted under a key derived from
`PULSAR_SECRET`, 32 random bytes in base64. Keep it: with another secret,
pulsar cannot decrypt its keys, so it never becomes ready; it answers
`/livez` until it has tried, and then exits with an error.

Clients and End-Users are listed in a registry file, a JSON document
named by `PULSAR_REGISTRY` and read at startup; pulsar refuses to start if
it is invalid. The comment of [internal/registry](internal/registry/registry.go)
describes its form. Client secrets and passwords appear in it only as
Argon2id hashes in the PHC string format, which the reference
implementation's `argon2` command prints:

```sh
# 2 passes over 32 MiB, one lane: above OWASP's minimum for Argon2id.
read -rs password && printf %s "$password" | argon2 "$(openssl rand -hex 16)" -id -t 2 -m 15 -p 1 -e
```

```sh
# Once per database; every later start needs the same value.
export PULSAR_SECRET="$(openssl rand -base64 32)"
# Listens on :8080; PULSAR_ADDR overrides. The issuer must be https, except
# on a loopback host. conformance/registry.json lists no Client or End-User;
# name a registry of your own to sign anyone in.
PULSAR_ISSUER=http://localhost:8080 \
  PULSAR_DATABASE_URL='postgres://localhost:5432/pulsar?sslmode=disable' \
  PULSAR_REGISTRY=conformance/registry.json \
  go run ./cmd/pulsar
curl -i localhost:8080/.well-known/openid-configuration
curl -i localhost:8080/jwks
curl -i localhost:8080/readyz
```

The login page is at `/login` under the issuer; an authorization request
from an End-User without a Login Session is sent there and resumes after
login. The Login Session cookie is `Secure`, which browsers keep over plain
http only on `localhost`.

As with libpq, anything `PULSAR_DATABASE_URL` leaves out is taken from the
`PG*` environment variables (`PGHOST`, `PGPASSWORD` and the rest), a
`PGSERVICE` service file and the password file.

To serve TLS itself, pulsar takes a PEM certificate and key in
`PULSAR_TLS_CERT` and `PULSAR_TLS_KEY`; give both or neither.

## Verifying it

With Go, Node.js, pnpm, jq and Claude Code installed, and a PostgreSQL server
whose URL, for a role that may create databases, is in
`PULSAR_TEST_DATABASE_URL`:

```sh
make setup     # once per clone: pinned tools, git hooks, Claude Code plugin
make verify    # what CI runs
```

### Checking conformance

With Docker (and Compose v2), openssl and jq installed:

```sh
make conformance
```

This runs pulsar and the
[OpenID conformance suite](https://gitlab.com/openid/conformance-suite)
at `release-v5.3.4` in Docker Compose, and the suite's
`oidcc-config-certification-test-plan`, which checks the discovery document
and the JWK Set. It exits non-zero on a failure or a warning that
`conformance/` does not list with a reason, and leaves the results in
`conformance/results/`. CI runs the same target on every pull request.
[conformance/README.md](conformance/README.md) describes the files it uses.

## How it is built

[AGENTS.md](AGENTS.md) is the map agents work from.
[docs/harness.md](docs/harness.md) lists every control on them and the
evidence for each, and [docs/research/](docs/research/) holds the dated
surveys the decisions rest on.

## About the name

A pulsar's period is its own, and anyone with a radio telescope can check it;
an ID token should be as easy to verify. The
[Pioneer plaques](https://en.wikipedia.org/wiki/Pioneer_plaque) and
Voyager's Golden Record place the Sun among 14 pulsars, and Voyager 1, which
carries that map, took the Pale Blue Dot photograph.

## License

[Apache 2.0](LICENSE).
