# pulsar

An OpenID Connect Provider in Go, built by AI agents under a harness in which
every control names the evidence behind it. The provider is the artifact; the
method is the subject. It is a reference implementation, not for production
use. So far it serves liveness and readiness checks, its discovery document,
its JWK Set, a login page that starts a Login Session, a consent page that
remembers the scopes an End-User allows each Client, and the authorization
code flow, with `prompt` and `max_age`, to an ID token and access token for
Clients that authenticate with `client_secret_basic`, `client_secret_post` or
`private_key_jwt`, and for public Clients, which must use PKCE with `S256`. A
redirect URI must equal one the Client registered, character for character,
but for the port of a public Client's loopback IP redirect URI such as
`http://127.0.0.1/callback`, which a native app may name with any port, as
RFC 8252 §7.3 requires; a `localhost` URI gets no such exception. A
Client may send `response_mode=form_post` once, with an `http` or `https`
redirect URI: every response pulsar sends to that URI, the code or an error,
then arrives in the body of a POST, from a page that submits itself by a
script its Content-Security-Policy allows by hash, with a button for a browser
without script. A repeated `response_mode`, or `form_post` with a redirect URI
of another scheme, is refused with `invalid_request` in the query. A
`private_key_jwt` assertion must name pulsar's issuer as its sole audience, as
RFC 10070 requires, so one naming the token endpoint is refused. A public
Client cannot prove its identity, so the consent page asks for it every time
rather than remembering. A public Client running in a browser on another
origin can redeem its code and refresh tokens, and call UserInfo, from the
origin of one of its redirect URIs. UserInfo answers any Client, confidential
or public, from the origins of its own redirect URIs, and the JWK Set answers
any origin. A confidential Client gets no such headers at the token endpoint,
since a browser cannot keep its secret. RFC 10017 recommends a
backend-for-frontend, a confidential Client on the server, over a Client that
runs in the browser. UserInfo returns the End-User's `sub` and the claims of
the `profile`, `email`, `address` and `phone` scopes granted, by GET or POST,
with the access token in the `Authorization` header or the body; the `claims`
parameter requests individual claims in the ID token or from UserInfo. A
Client may ask, with one `resource` parameter (RFC 8707), for an access token
for a Resource Server the registry lets it request, and for at least one of
that Resource Server's scopes beside OpenID Connect's; the consent page lists
them, with their descriptions, under its identifier. That access token's
`aud` is the Resource Server's identifier and its `scope` holds only that
Resource Server's scopes, so UserInfo refuses it; the ID token is unchanged.
A refresh keeps the Resource Server. A `resource` other than the one
authorized, not permitted, unregistered, malformed or repeated, or one
without any of its scopes, gets `invalid_target`. Without `resource`, the
access token is for UserInfo, as before. A
request with `offline_access` and `prompt=consent` asks the End-User for
offline access, and if they allow it, the token response carries a refresh
token. The Client redeems it with the `refresh_token` grant, for a narrower
scope if it asks, for a new access token, ID token and refresh token, for up
to thirty days; each refresh token is redeemed once. A refresh token already
redeemed, presented again by its own Client while its Refresh Token Family
lives, revokes the whole family, with no grace period: its refresh tokens are
refused from then on, and UserInfo refuses its access tokens. A second
redemption of a code that is otherwise valid, by its own Client, with its
redirect URI, and with a matching `code_verifier` exactly when the code has a
challenge, revokes the access tokens issued from it and, for as long as the
family lives, the Refresh Token Family it started. A Client may revoke a
refresh token or access token issued to it at the revocation endpoint (RFC
7009), authenticating as at the token endpoint. A refresh token revokes its
whole Refresh Token Family and the access tokens issued in it; an access
token revokes only itself. Revoking an access token takes effect at
UserInfo; a Resource Server that verifies the JWT itself accepts it until
it expires, at most ten minutes later. While an End-User is out of
the registry, no code or refresh token issued for them is redeemed, and
UserInfo refuses their access tokens; a Client out of the registry cannot
authenticate, so it redeems neither. Removal revokes nothing, so one added
back has the tokens not yet expired again. Every 15 minutes, each replica
deletes the codes no longer kept for a second redemption to revoke, the
expired access tokens, client assertions and Login Sessions, the ended Refresh
Token Families with their refresh tokens, and the counts of login attempts
forgotten a day after the last. `pulsar keys rotate` rotates the signing key.
A Client may send the End-User to the logout endpoint, the
`end_session_endpoint` of discovery, by GET or POST (OpenID Connect
RP-Initiated Logout 1.0). pulsar asks the End-User to confirm every time,
naming the Client when an `id_token_hint` or a `client_id` identifies it;
confirming ends the Login Session, and declining keeps it. pulsar then
returns the End-User to the `post_logout_redirect_uri`, with `state` and
nothing else, only if the identified Client registered exactly that URI, and
otherwise shows a page that says whether they are signed out. An
`id_token_hint` must be an ID token pulsar issued to a registered Client,
and a `client_id` sent with it must name that Client. The hint may have
expired, and may be signed by a key that `pulsar keys rotate` replaced. That
key leaves the JWK Set eleven minutes after the new key starts signing, but
pulsar accepts hints it signed, and nothing else it signed, until ten hours
and a minute after the new key started signing: the longest a Login Session
in which the old key signed can last from then, plus a reload interval's
margin. A hint refused, or a `client_id` that does not match it,
gets an error page and logs no one out. The request is carried in
the confirmation form's body, so no URL pulsar sends the browser to holds
the hint. Logout revokes no refresh token and no access token.
The OpenID conformance suite's Config OP, Basic OP, Form Post Basic and
RP-Initiated Logout plans run against it in CI; on 2026-11-06, at commit
`8d6ab47`, the first two finished with no failures, as
[Checking conformance](#checking-conformance) details.

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

Resource Servers, Clients and End-Users are listed in a registry file, a
JSON document named by `PULSAR_REGISTRY` and read at startup; pulsar refuses
to start if it is invalid. The comment of [internal/registry](internal/registry/registry.go)
describes its form. Client secrets and passwords appear in it only as
Argon2id hashes in the PHC string format. A Resource Server is registered by
its identifier, an absolute URI without a fragment other than the issuer,
with at least one scope, each with a description; none of its scopes may be
one of OpenID Connect's or another Resource Server's. Each Client lists the
Resource Servers it may request.

`pulsar client-secret` generates a Client secret and prints it with its
hash, so that the secret is generated by the authorization server, as
RFC 6819 §5.1.4.2.2 has it. The secret is 256 bits from `crypto/rand` in
unpadded base64url, which needs no escaping in `client_secret_basic`, and
guessing cannot find it (RFC 6749 §10.10). The command reads no
configuration, and the secret is shown only in its output: give
`client_secret` to the Client and copy `client_secret_hash` into the
registry file.

```sh
go run ./cmd/pulsar client-secret
# {"client_secret":"…","client_secret_hash":"$argon2id$v=19$m=19456,t=2,p=1$…$…"}
```

pulsar cannot tell how a hash was made, so it also accepts one made
elsewhere; the operator must then make the secret it hashes at least 256
bits from a cryptographically strong random source. Logins are throttled
per End-User; Client secrets are not, since anyone could hold up a
Client whose failed attempts were counted
([ADR 0005](docs/adr/0005-logins-throttled-per-end-user-by-delay.md)).

The reference implementation's `argon2` command prints a password's
hash:

```sh
# 2 passes over 32 MiB, one lane: above OWASP's minimum for Argon2id.
read -rs password && printf %s "$password" | argon2 "$(openssl rand -hex 16)" -id -t 2 -m 15 -p 1 -e
```

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
login. The logout endpoint is at `/logout`. The Login Session cookie is
`Secure`, which browsers keep over plain http only on `localhost`.

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
make setup     # once per clone: pinned tools, git hooks, Claude Code plugins
make verify    # what CI runs
```

### Checking conformance

With Docker (and Compose v2), openssl and jq installed:

```sh
make conformance
```

This runs pulsar and the
[OpenID conformance suite](https://gitlab.com/openid/conformance-suite)
at `release-v5.3.4` in Docker Compose, and four of the suite's plans:
`oidcc-config-certification-test-plan`, which checks the discovery document
and the JWK Set; `oidcc-basic-certification-test-plan`, which signs an
End-User in through the authorization code flow with static Clients and
discovery, and checks the responses of the authorization, token and
UserInfo endpoints; and `oidcc-formpost-basic-certification-test-plan`,
which runs the same modules with `response_mode=form_post` and checks that
every authorization response, errors too, arrives by POST. The Form Post
plan does not check `response_modes_supported`, the form-post page's
headers, or a browser without script; only pulsar's own tests do. The
Basic OP plan's `oidcc-refresh-token` module, which the Form Post plan
repeats, redeems a refresh token once with `scope` and once without,
checks the response, the refreshed ID token, and UserInfo with the new
access token, and checks
that another Client's refresh token is refused. It never presents a
refresh token twice
([research](docs/research/refresh-tokens.md#the-suites-oidcc-refresh-token-module)),
so it tests neither rotation nor reuse detection: only pulsar's own tests
check that each refresh token is redeemed once, and that one presented
again, or a code replayed, revokes its Refresh Token Family. No plan in
that release tests token revocation (RFC 7009); only pulsar's own tests
do. The fourth
plan, `oidcc-rp-initiated-logout-certification-test-plan`, signs the
End-User in and sends them to the logout endpoint by GET, with only
`id_token_hint`, `post_logout_redirect_uri` and `state`. Two of its modules
check the redirect back and then that `prompt=none` fails; eight check only
that pulsar does not redirect, and end in `REVIEW`
([conformance/README.md](conformance/README.md#pages-a-person-would-review)).
It never sends `client_id`, a POST or an expired hint, so pulsar's own
tests alone check those. The suite's browser automation fills in the login
and consent pages, and confirms the logout. The run exits
non-zero on a failure, a warning or a skipped module that `conformance/`
does not list with a reason, and leaves the results in
`conformance/results/`. CI runs the same target on every pull request.

[conformance/README.md](conformance/README.md) describes the files it uses.

### Running the examples

[examples/](examples/README.md) holds consumers of pulsar in a Go module of
their own, which does not require pulsar's: a web app, a confidential
Client on the server that keeps tokens from the browser; an API, a
Resource Server that verifies pulsar's access tokens itself; and a
command-line public Client that signs in through a loopback redirect. Both
Clients call the API. They use only `golang.org/x/oauth2`,
`github.com/coreos/go-oidc` and `github.com/go-jose/go-jose`. With Docker
(and Compose v2), openssl and Go installed:

```sh
make examples
```

This runs pulsar in Docker Compose with the examples' registry, and the
examples' tests against it, over the network. They show that those
libraries work with pulsar: the web app signs in with its secret, calls
the API, refreshes its access token twice, and at logout revokes its
refresh token, which pulsar then refuses, and signs out at pulsar's logout
endpoint, which asks the End-User to confirm and returns them with the
web app's `state`. No response the browser receives holds an access or
refresh token, and the ID token appears only as `id_token_hint`: in the
`Location` of the web app's redirect to pulsar's logout endpoint, and in
the form of pulsar's logout page. The CLI signs in with PKCE through a
loopback redirect on a port the operating system chose, gets an access
token for the API with `resource`, and calls the API, which accepts it.
The API refuses no token, a token for UserInfo, a token at its `exp` by
the API's clock, a changed or unsigned token and an ID token with 401,
and a token without the route's scope with 403; and after `pulsar keys
rotate` it accepts tokens signed with the new key. No browser runs: the
tests act as one with Go's HTTP client.
[examples/README.md](examples/README.md#what-the-tests-prove) lists what
they do not prove. CI runs the same target on every pull request.

On 2026-11-06, CI ran the Config OP and Basic OP plans against commit
`8d6ab47`, on `main`, with no failures; the Form Post Basic and
RP-Initiated Logout plans were added after that run, and no result of
them is recorded here yet.
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
