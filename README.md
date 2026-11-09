# pulsar

An OpenID Connect Provider in Go, built by AI agents under a harness that has
to prove it helps. The provider is the artifact; the method is the subject.
It is a reference implementation, not for production use. So far it serves
liveness and readiness checks, its discovery document, its JWK Set, a login
page that starts a Login Session, a consent page that remembers the scopes
an End-User allows each Client, and the authorization code flow, with
`prompt` and `max_age`, to an ID token and access token for Clients that
authenticate with `client_secret_basic`, `client_secret_post` or
`private_key_jwt`, and for public Clients, which must use PKCE with `S256`.
A `private_key_jwt` assertion must name pulsar's issuer as its sole
audience, as RFC 10070 requires, so one naming the token endpoint is
refused.
A public Client cannot prove its identity, so the consent page asks for it
every time rather than remembering. The token endpoint sends no CORS
headers, so a public Client running in a browser on another origin cannot
reach it. UserInfo returns the End-User's `sub` and the claims of the
`profile`, `email`, `address` and `phone` scopes granted, by GET or POST,
with the access token in the `Authorization` header or the body; the
`claims` parameter requests individual claims in the ID token or from
UserInfo. A request with `offline_access` and `prompt=consent` asks the
End-User for offline access, and if they allow it, the token response
carries a refresh token. The Client redeems it with the `refresh_token`
grant, for a narrower scope if it asks, for a new access token, ID token
and refresh token, for up to thirty days; each refresh token is redeemed
once. A refresh token already redeemed, presented again by its own Client
while its Refresh Token Family lives, revokes the whole family, with no
grace period: its refresh tokens are refused from then on, and UserInfo
refuses its access tokens. A second redemption
of a code that is otherwise valid, by its own Client, with its redirect
URI, and with a matching `code_verifier` exactly when the code has a
challenge, revokes the access tokens issued from it and, for as long as
the family lives, the Refresh Token Family it started. While an End-User
is out of the registry, no code or refresh token issued for them is
redeemed, and UserInfo refuses their access tokens; a Client out of the
registry cannot authenticate, so it redeems neither. Removal revokes
nothing, so one added back has the tokens not yet expired again. Every
15 minutes, each replica deletes the codes no longer kept for a second
redemption to revoke, the expired access tokens, client assertions and
Login Sessions, the ended Refresh Token Families with their refresh
tokens, and the counts of login attempts forgotten a day after the last. `pulsar keys
rotate` rotates the signing key. The OpenID conformance
suite's Config OP and Basic OP plans run against it in CI; on 2026-11-06,
at commit `8d6ab47`, they finished with no failures, as [Checking
conformance](#checking-conformance) details.

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

`pulsar keys rotate` stores a new signing key and exits; it reads the same
environment as the server. Every replica publishes the key in its JWK Set at
its next reload, within a minute, and signs with it two minutes after it is
stored: one reload interval plus the JWK Set's one-minute cache lifetime, so
that, provided every replica reloads on time and Clients honor
`Cache-Control`, every replica, and every JWK Set a Client has cached, has
the key first. The key it replaces stays in the JWK Set for eleven minutes more,
the ten-minute token lifetime plus a reload interval, by when every token it
signed has expired.

Run it only once every replica runs a release that has it, since an earlier
release signs with a new key at once, and on a host whose clock agrees with
the replicas'. It refuses a database pulsar has never started against, and
a `PULSAR_SECRET` other than the one the keys are stored under. It does not
revoke a key: a leaked key stays in the JWK Set, so Clients accept tokens
signed with it, for at least thirteen minutes.

```sh
# The same environment as the server's, PULSAR_SECRET included (below).
PULSAR_ISSUER=http://localhost:8080 \
  PULSAR_DATABASE_URL='postgres://localhost:5432/pulsar?sslmode=disable' \
  PULSAR_REGISTRY=conformance/registry.json \
  go run ./cmd/pulsar keys rotate
```

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

A client secret must be at least 256 bits from a cryptographically strong
random source, such as `openssl rand -base64 32` prints, so that guessing
cannot find it (RFC 6749 §10.10, RFC 6819 §5.1.4.2.2). Logins are
throttled per End-User; client secrets are not, since anyone could hold
up a Client whose failed attempts were counted
([ADR 0005](docs/adr/0005-logins-throttled-per-end-user-by-delay.md)).

```sh
# Once per database; every later start needs the same value.
export PULSAR_SECRET="$(openssl rand -base64 32)"
# Listens on :8080; PULSAR_ADDR overrides. The issuer must be https, except
# on a loopback host. conformance/registry.json lists only the conformance
# suite's Clients, which redirect to the suite, and an End-User whose
# password is published; name a registry of your own to sign anyone in.
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
at `release-v5.3.4` in Docker Compose, and two of the suite's plans:
`oidcc-config-certification-test-plan`, which checks the discovery document
and the JWK Set, and `oidcc-basic-certification-test-plan`, which signs an
End-User in through the authorization code flow with static Clients and
discovery, and checks the responses of the authorization, token and
UserInfo endpoints. Its `oidcc-refresh-token` module redeems a refresh
token once with `scope` and once without, checks the response, the
refreshed ID token, and UserInfo with the new access token, and checks
that another Client's refresh token is refused. It never presents a
refresh token twice
([research](docs/research/refresh-tokens.md#the-suites-oidcc-refresh-token-module)),
so it tests neither rotation nor reuse detection: only pulsar's own tests
check that each refresh token is redeemed once, and that one presented
again, or a code replayed, revokes its Refresh Token Family. The suite's
browser automation fills in the login and consent pages. The run exits
non-zero on a failure, a warning or a skipped module that `conformance/`
does not list with a reason, and leaves the results in
`conformance/results/`. CI runs the same target on every pull request.

[conformance/README.md](conformance/README.md) describes the files it uses.

On 2026-11-06, CI ran both plans against commit `8d6ab47`, on `main`,
with no failures.
Of the Basic OP plan's 35 modules, 28 passed; one ended in a warning,
since pulsar never returns `acr`; two were skipped, since pulsar issues no
refresh tokens and supports no request objects; and four ended in
`REVIEW`, which the suite leaves for a person to judge from the page it
records, and which no person has yet reviewed. That is a result of the
suite's checks, not an OpenID certification.

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
