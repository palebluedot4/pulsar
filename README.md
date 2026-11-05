# pulsar

An OpenID Connect Provider in Go, built by AI agents under a harness that has
to prove it helps. The provider is the artifact; the method is the subject.
It is a reference implementation, not for production use. So far it serves
liveness and readiness checks and its discovery document; the other OpenID
endpoints are next.

## Running it

pulsar keeps its state in PostgreSQL, in a database that must exist. It
serves at once and applies its migrations meanwhile: `/readyz` answers 503
until they are applied, and pulsar exits if they fail. After that `/readyz`
answers 200 while a ping through its connection pool succeeds, and 503 when
one fails.

```sh
# Listens on :8080; PULSAR_ADDR overrides. The issuer must be https, except
# on a loopback host.
PULSAR_ISSUER=http://localhost:8080 \
  PULSAR_DATABASE_URL='postgres://localhost:5432/pulsar?sslmode=disable' \
  go run ./cmd/pulsar
curl -i localhost:8080/.well-known/openid-configuration
curl -i localhost:8080/readyz
```

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
