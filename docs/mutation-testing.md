# Mutation testing

`repocheck` proves that a test cites each requirement, not that the test
fails when the requirement is broken. Mutation testing measures the second:
[gremlins](https://github.com/go-gremlins/gremlins) changes one operator at a
time in the code, `<` to `<=` or `==` to `!=`, and runs the tests. A mutant
the tests notice is killed; one they do not notice lived, and marks code whose
behavior no test checks.

It is a measurement, not a gate (#5). gremlins is in its 0.x releases, and a
run over the packages below took 79 minutes on 2026-11-10. Why gremlins, and
why not a gate: `docs/research/go-and-terraform.md` and
`docs/research/evals.md` ("Issue #5").

## Running it

```sh
make mutation
make mutation MUTATION_PACKAGES=internal/login
```

`MUTATION_PACKAGES` defaults to the packages that hold the security-critical
code #5 names:

| Package             | What it holds                                                                                        |
| ------------------- | ---------------------------------------------------------------------------------------------------- |
| `internal/oidc`     | The authorization, token, userinfo and revocation endpoints; PKCE; private_key_jwt client assertions |
| `internal/registry` | Redirect URI matching; Client secret and End-User password verification                              |
| `internal/signing`  | The signing keys tokens are signed with, and the JWKS                                                |

Each package's results go to `mutation/<package>.json`, which git ignores:
every mutant, its position, its mutator and its status.

Nothing else may use the test database while it runs. One run of the suite
held up to about 70 of PostgreSQL's default 100 connections, so a second run
alongside, from another worker, another session's `make check` or a Stop
hook, can fail tests with SQLSTATE 53300 ("too many clients already"), and
gremlins counts each mutant whose tests failed that way as killed, which
raises the score with nothing to show for it. A server of the run's own
avoids that:

```sh
PULSAR_TEST_DATABASE_URL=postgres://<role>@localhost:<port>/postgres make mutation
```

On a shared server, a run is clean only if the server's log has no such
error between its start and its end; with Postgres.app:

```sh
grep 'too many clients' ~/Library/Application\ Support/Postgres/var-17/postgresql.log | tail
```

## How it is configured, and why

- **`--integration --coverpkg ./...`.** `internal/oidc` has no tests of its
  own: `internal/server` tests it over HTTP. Without `--integration`,
  gremlins measures coverage, and runs tests, in the mutated package alone,
  so no mutant there would count as covered and none would run; without
  `--coverpkg`, coverage would count no line of it either. With both, each
  mutant runs the whole suite, which is why a run is slow.
- **`go clean -testcache` before each package.** gremlins times one run of
  the suite and gives each mutant three times as long before calling it
  timed out. A cached run takes a second, so every mutant would time out.
  The mutants' own runs keep the cache, so a package that cannot import the
  mutated one is not run again.
- **`--workers 1`, not a variable.** The connections above: a second worker
  is a second run of the suite alongside.
- **`$(GO)`'s toolchain first on `PATH`.** gremlins runs the `go` it finds
  there, not the one that built it.
- **`--exclude-files '(^|/)internal/queries/'`.** sqlc generates that code;
  `make sqlc-check` already checks it against its queries.
- **Mutators.** gremlins' defaults: arithmetic, conditional boundaries,
  conditional negation, increment and decrement, and inverted negatives.
  It does not, by default, invert `&&` and `||`, `break` and `continue`, or
  assignments.

Not used: `--diff`, which mutates only the lines a change touches. In
v0.6.0 it names changed files from the module root, `internal/oidc/token.go`,
and mutants from the package given, `token.go`, so with a package it matches
nothing and skips every mutant; checked 2026-11-10 against a commit that
changed `internal/oidc`.

## Reading the results

- **Test efficacy** is killed / (killed + lived): of the mutants the tests
  reach, the share they catch. Timed-out mutants count in neither.
- **Mutator coverage** is (killed + lived) / (killed + lived + not covered):
  the share of mutants in code that Go's coverage profile counts as run.
- **Not covered** is not the same as untested. gremlins runs a mutant only
  if its position falls inside a block of the coverage profile, and Go's
  profile has no block for the conditions of a `case` clause, which sit
  between the `switch` and the clause's body, nor for package-level
  declarations. A mutant there is never run, however thoroughly the tests
  exercise it: it lowers mutator coverage and is left out of test efficacy,
  so no score says whether the tests would catch it. The `case` conditions
  are [#298](https://github.com/go-gremlins/gremlins/issues/298), open as
  of 2026-11-11.
- **Test efficacy is an upper bound.** In v0.6.0, a mutant that does not
  compile is counted as killed: `go test` exits 1 on a build failure, as it
  does on a failing test, so gremlins' "not viable" status is never reached
  ([#321](https://github.com/go-gremlins/gremlins/issues/321), open as of
  2026-11-11). Some killed mutants may be ones no test had to catch.
- Scores compare only at the same gremlins version, which each run below
  records. Dependabot updates gremlins with the other tools in
  `tools/go.mod`, and a release may change its default mutators or how it
  matches coverage.
- A lived mutant is not always a missing test. An equivalent mutant changes
  the code without changing what it does, such as `<` to `<=` where the two
  are never equal; no test can kill it. Each one is decided by reading the
  code.

## Results

### 2026-11-10

gremlins v0.6.0, Go 1.27.3, PostgreSQL 17.2 (Postgres.app), at `dfbfa19`;
79 minutes, with no SQLSTATE 53300 in the server's log while it ran. It ran
every test of every mutant uncached (`GOFLAGS=-count=1`), before the target
cleared the cache only for the baseline.

| Package             | Killed | Lived | Timed out | Not covered | Test efficacy | Mutator coverage |
| ------------------- | -----: | ----: | --------: | ----------: | ------------: | ---------------: |
| `internal/oidc`     |    238 |     9 |         0 |          72 |        96.36% |           77.43% |
| `internal/registry` |     94 |     9 |         1 |          48 |        91.26% |           68.21% |
| `internal/signing`  |     44 |     2 |         0 |           5 |        95.65% |           90.20% |

Each test efficacy is an upper bound: how many of the killed mutants did
not compile is not known (above). Test efficacy also leaves out much of
what #5 names. Of the 125 mutants not
covered, 111 are conditions of `case` clauses (64 in `internal/oidc`, 47 in
`internal/registry`) and 13 are in package-level declarations; one alone,
the `Retry-After` header at `internal/oidc/token.go:117`, is in a statement
no test runs. The `case` conditions include the PKCE checks in
`internal/oidc/authorize.go` and `pkce.go`, the checks on a private_key_jwt
assertion in `assertion.go`, those on an access token in `userinfo.go`, and
the parsing of redirect URIs in `internal/registry/registry.go`: gremlins
listed their mutants but ran none of them. Nor was any `&&` or `||` inverted, which many of the
checks that were mutated are built from.

Mutants that lived, and the one that timed out, with the line each changed.
Which are equivalent and which call for a test is not yet decided.

| Position                             | Mutator                      | Line                                                                                     |
| ------------------------------------ | ---------------------------- | ---------------------------------------------------------------------------------------- |
| `internal/oidc/authorize.go:345`     | Conditionals negation        | `if err := login.WriteConsentPage(w, page); err != nil {`                                |
| `internal/oidc/authorize.go:624`     | Conditionals boundary        | `if req.maxAge > 0 && !answered && now.Unix()-authTime.Unix() > req.maxAge {`            |
| `internal/oidc/logout.go:106`        | Conditionals negation        | `if err := login.WriteLogoutPage(w, page); err != nil {`                                 |
| `internal/oidc/logout.go:173`        | Conditionals negation        | `if err := login.WriteLogoutOutcomePage(w, signedOut); err != nil {`                     |
| `internal/oidc/revocation.go:88`     | Conditionals negation        | `if strings.Count(token, ".") == 2 {`                                                    |
| `internal/oidc/token.go:116`         | Conditionals boundary        | `if tokErr.retryAfter > 0 {`                                                             |
| `internal/oidc/token.go:116`         | Conditionals negation        | `if tokErr.retryAfter > 0 {`                                                             |
| `internal/oidc/token.go:872`         | Conditionals negation        | `if err := p.queries.StopKeepingAuthorizationCode(ctx, …); err != nil {`                 |
| `internal/oidc/token.go:945`         | Conditionals boundary        | `if u, ok := p.registry.EndUser(t.subject); ok && len(t.idTokenClaims) > 0 {`            |
| `internal/registry/argon2.go:78`     | Conditionals boundary        | `if len(salt) < minSaltSize {`                                                           |
| `internal/registry/argon2.go:81`     | Conditionals boundary        | `if len(key) < minKeySize {`                                                             |
| `internal/registry/registry.go:293`  | Conditionals boundary        | `if end < 0 {`                                                                           |
| `internal/registry/registry.go:299`  | Conditionals boundary        | `if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.Contains(host[i:], "]") {` |
| `internal/registry/registry.go:479`  | Conditionals boundary        | `if largest := r.largestHash(); largest > 0 {`                                           |
| `internal/registry/registry.go:480`  | Arithmetic base (timed out)  | `r.hashing = semaphore.NewWeighted(int64(runtime.GOMAXPROCS(0)) * largest)`              |
| `internal/registry/registry.go:739`  | Conditionals boundary, twice | `return c < 0x21 \|\| c > 0x7e \|\| c == '"' \|\| c == '\\'`                             |
| `internal/registry/registry.go:876`  | Conditionals boundary        | `if i := strings.IndexFunc(raw, notURIChar); i >= 0 {`                                   |
| `internal/registry/registry.go:1018` | Conditionals boundary        | `if len(r.usernames) > 0 {`                                                              |
| `internal/signing/signing.go:193`    | Conditionals negation, twice | `if err := s.reload(ctx); err != nil && ctx.Err() == nil {`                              |
