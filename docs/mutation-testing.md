# Mutation testing

`repocheck` proves that a test cites each requirement, not that the test
fails when the requirement is broken. Mutation testing measures the second:
[go-mutesting](https://github.com/avito-tech/go-mutesting) changes the code
one way at a time, `<` to `<=`, a term of `&&` to `true`, an `if` body or a
statement removed, and the tests run against each change. A mutant the tests
notice is killed; one they do not notice lived, and marks code whose
behavior no test checks.

It is a measurement, not a gate (#5): a run over the packages below took
almost six hours on 2026-11-11. Why go-mutesting, and why it replaced
gremlins: `docs/research/mutation-testing-tools.md`. Why not a gate:
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

It measures the commit checked out, not uncommitted changes: it checks HEAD
out into a working tree of its own and removes it afterwards. Each
package's results go to `mutation/`, which git ignores, and its counts to
the console, from the report rather than go-mutesting's own score, which
counts mutants that did not compile as killed: `<package>.json`,
go-mutesting's report of every mutant with its mutator, its source before
and after and its status, and `<package>.log`, which gives each mutant that
lived, timed out or met a full database with its diff.

Nothing else should use the test database while it runs. One run of the
suite held up to about 70 of PostgreSQL's default 100 connections, so a
second run alongside, another session's `make check` or a Stop hook, can
fail tests with SQLSTATE 53300 ("too many clients already"). The exec
script reports such a mutant as `DATABASE FULL`, neither killed nor lived;
run it again alone (below). It counts any other failure as a kill, so the
target runs the suite once unmutated first, and stops if it fails, as it
does without a database. A database that stops during the run is not
caught: every mutant after it would count as killed, so a run whose log
ends in an unbroken line of kills is checked against the server's log.

## How it is configured, and why

- **`scripts/mutation-exec.sh` tests each mutant**, not go-mutesting's own
  exec, which reads `go test`'s exit status 1 as killed whether a test
  failed, the mutant did not compile or a test timed out. The script
  builds the mutated package first and skips a mutant that does not
  compile; runs every package's tests, not only the mutated one's, because
  most of `internal/oidc` is tested only by `internal/server`, over HTTP;
  and reports a timeout (`TIMED OUT`, after
  `MUTATION_TEST_TIMEOUT`, 90 seconds by default, per package) and a full
  database apart from kills. Packages a mutant cannot reach keep their
  cached results.
- **A working tree of its own.** The script writes each mutant over the
  source file and puts the original back when it exits, so whatever else
  reads that working tree meanwhile, an editor, another session, a Stop
  hook's `make check`, would see the mutant.
- **`scripts/go-mutesting.yml`**: `skip_without_test: false`, since most
  files of `internal/oidc` have no test file of their own, and JSON
  output.
- **One mutant at a time.** go-mutesting runs them in sequence; the
  database above is why it matters.
- **`$(GO)`'s toolchain first on `PATH`.** The script runs the `go` it finds
  there.
- **Mutators.** All that go-mutesting registers, as
  `go-mutesting --list-mutators` names them: `statement/remove`,
  `branch/if`, `branch/else` and `branch/case`, which remove a statement or
  a body; `expression/remove`, which replaces a term of `&&` or `||` with
  `true` or `false`; `expression/comparison`, boundary changes;
  `arithmetic/base`, `arithmetic/bitwise`, `arithmetic/assignment` and
  `arithmetic/assign_invert`; `numbers/incrementer` and
  `numbers/decrementer`; and `loop/break`, `loop/condition` and
  `loop/range_break`. Its negation
  of comparisons, `==` to `!=`, is written but not registered
  ([#55](https://github.com/avito-tech/go-mutesting/issues/55), open as of
  2026-11-11). `internal/queries` is a package of its own, so it is not
  mutated; sqlc generates it and `make sqlc-check` checks it.

### Running one mutant again

The log gives a mutant's diff, from `--- original`, which `patch` applies
to a copy; the script then tests it as go-mutesting would, in the working
tree whose file it replaces:

```sh
patch -o "$TMPDIR/mutant.go" internal/registry/registry.go < mutant.diff
MUTATE_CHANGED="$TMPDIR/mutant.go" MUTATE_ORIGINAL=internal/registry/registry.go \
  MUTATE_PACKAGE=./internal/registry scripts/mutation-exec.sh; echo $?
```

Exit status 0 is killed, 1 lived, 2 did not compile, 3 timed out and 4 a
full database.

## Reading the results

- **Test efficacy** is killed / (killed + lived): of the mutants that
  compile, the share the tests catch. Mutants that do not compile and
  those that timed out count in neither.
- go-mutesting's summary counts as duplicated the mutants whose source is
  the same as an earlier one's, and does not run them; the counts below
  leave them out.
- A lived mutant is not always a missing test. Google, which runs mutation
  testing at code review, does not aim to kill every mutant
  ([Practical Mutation Testing at Scale](https://ar5iv.labs.arxiv.org/html/2102.11378)):
  a developer judges each one. Each mutant that lived here is put in one
  of five classes, by reading the code:
  - **Needs a test**: the mutant changes what a Client, an End-User or the
    operator can observe, and no test notices.
  - **Equivalent**: it changes the code without changing what it does,
    such as a check that a later one always repeats, a cache whose miss
    recomputes the same value, or a mutant whose source is the original's.
    No test can kill it.
  - **Cannot fail**: it removes the handling of an error the call cannot
    return with the arguments it is given, such as AES with a key of
    AES-256's size, or encoding values that always encode.
  - **Log or capacity only**: it changes only whether a line is logged, or
    the size of a semaphore, which Google calls arid nodes and does not
    mutate.
  - **Database or I/O failure**: it removes the handling of a failure of
    PostgreSQL, of saving a session, or of writing a page. A test would
    have to make PostgreSQL fail at that step, without a mock (#100).
- Scores compare only at the same go-mutesting commit and with the same
  exec script, which each run below records.

## Results

### 2026-11-11, go-mutesting

go-mutesting at `9ce5f73`, through `scripts/mutation-exec.sh`, Go 1.27.3,
PostgreSQL 17.2 (Postgres.app), at `94074e6`, whose code in the three
packages is that of the gremlins run below; 5 hours 41 minutes. The
scores are those of the tests before #97 added any.

| Package             | Killed | Lived | Did not compile | Timed out | Test efficacy |
| ------------------- | -----: | ----: | --------------: | --------: | ------------: |
| `internal/oidc`     |    533 |   161 |             143 |         0 |        76.80% |
| `internal/registry` |    284 |    77 |              60 |         1 |        78.67% |
| `internal/signing`  |     44 |    42 |              21 |         0 |        51.16% |

The mutant that timed out divides the hashing semaphore's weight by the
largest hash's memory instead of multiplying, so a login waits for weight
that never frees; it timed out again with 300 seconds.

At every line where a gremlins mutant lived, those of gremlins' negation
included, a go-mutesting mutant lived too, on that line or in the body of
the `if` it begins.

Each mutant that lived was classed by reading the code, and each one
classed as needing a test got one, in the commits of #97. Writing them
showed 13 to be equivalent after all, which the classes below count
there: in each, another step already refuses or filters what the mutant
lets through, with the same response, or the case it changes cannot
arise.

| Line                                | Mutant                                  | Why it is equivalent                                                                                  |
| ----------------------------------- | --------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `internal/oidc/authorize.go:466`    | a Resource Server's scope check removed | The consent page and the tokens issued keep only the scopes of the Resource Server requested          |
| `internal/oidc/logout.go:99`        | `&& known` replaced with `true`         | A Login Session with an End-User means the cookie was sent, so `known` is true whenever `ok` is       |
| `internal/oidc/revocation.go:64`    | the request's read error ignored        | Its parameters are then nil, so the request fails for want of `token` with the same `invalid_request` |
| `internal/oidc/token.go:127`        | the request's read error ignored        | As above, for want of `grant_type`                                                                    |
| `internal/oidc/token.go:172`        | the body's read error ignored           | As above                                                                                              |
| `internal/oidc/token.go:116`        | `retryAfter > 0` to `> 1`               | A duration of one nanosecond is never set                                                             |
| `internal/registry/registry.go:290` | the `http://` prefix check removed      | Without it the scheme ends the host, which then has an empty port, and is refused                     |
| `internal/registry/registry.go:313` | the bracket check's `return` removed    | The registry refuses an IPv4 address in brackets, and `url.Parse` an IPv6 one without                 |
| `internal/registry/registry.go:312` | the IPv6 half of the check replaced     | As above                                                                                              |
| `internal/registry/registry.go:312` | the IPv4 half of the check replaced     | As above                                                                                              |
| `internal/registry/registry.go:823` | `!k.Valid()` replaced with `false`      | go-jose refuses a JWK that is not valid when it decodes the JWK Set                                   |
| `internal/signing/signing.go:261`   | the error of `Active` ignored           | The zero key that follows makes signing fail with an error all the same                               |
| `internal/signing/signing.go:527`   | the PKCS #8 decoding error ignored      | The nil key that follows is refused as not an RSA key                                                 |

Where a line appears in more than one class, its mutants differ:

| Line                                | Mutant                                      | Class                                                        |
| ----------------------------------- | ------------------------------------------- | ------------------------------------------------------------ |
| `internal/oidc/authorize.go:217`    | the `if` body, its log and its 500, removed | Database or I/O failure                                      |
| `internal/oidc/authorize.go:217`    | the log call alone removed                  | Log or capacity only                                         |
| `internal/oidc/authorize.go:225`    | as at 217, after saving the Login Session   | Database or I/O failure; Log or capacity only                |
| `internal/oidc/authorize.go:346`    | as at 217, after writing the consent page   | Database or I/O failure; Log or capacity only                |
| `internal/oidc/authorize.go:624`    | `max_age > 1`                               | Needs a test                                                 |
| `internal/oidc/authorize.go:624`    | `>= 0`, `> -1`                              | Equivalent: they change only `max_age=0`, handled apart      |
| `internal/oidc/issuer.go:81`        | `ip != nil && true`                         | Needs a test                                                 |
| `internal/oidc/issuer.go:81`        | `true && ip.IsLoopback()`                   | Equivalent: a nil IP is not loopback                         |
| `internal/oidc/token.go:116`        | `>= 0`, `> -1`                              | Needs a test                                                 |
| `internal/oidc/token.go:116`        | `> 1`                                       | Equivalent (table above)                                     |
| `internal/oidc/userinfo.go:122`     | the `if` body, its log and its 500, removed | Cannot fail: the claims always encode                        |
| `internal/oidc/userinfo.go:122`     | the log call alone removed                  | Log or capacity only                                         |
| `internal/registry/argon2.go:99`    | the `return` removed                        | Needs a test                                                 |
| `internal/registry/argon2.go:99`    | `0` returned as `1` with the error          | Equivalent: no caller reads the value beside an error        |
| `internal/registry/registry.go:293` | `end < -1`                                  | Needs a test                                                 |
| `internal/registry/registry.go:293` | `end <= 0`, `end < 1`                       | Equivalent: `end` is 0 only with no host, refused either way |
| `internal/registry/registry.go:823` | `!k.IsPublic()` replaced with `false`       | Needs a test                                                 |
| `internal/registry/registry.go:823` | `!k.Valid()` replaced with `false`          | Equivalent (table above)                                     |

| Class                   | `internal/oidc` | `internal/registry` | `internal/signing` |
| ----------------------- | --------------: | ------------------: | -----------------: |
| Needs a test            |              41 |                  48 |                  9 |
| Equivalent              |              44 |                  24 |                  9 |
| Cannot fail             |              23 |                   0 |                 14 |
| Log or capacity only    |              12 |                   5 |                  3 |
| Database or I/O failure |              41 |                   0 |                  7 |

Each of the 98 that needed a test was then run again by hand, with the
new tests, against the tests of the packages that reach it, and each was
killed. One, at `internal/oidc/claims.go:231`, which turns the `continue`
after the sub Claim into a `break`, is killed only if sub is not the
last of the claims requested that is read, in an order Go does not fix;
`TestClaimsParameterSubAmongOthers` sends eight others three times, so
that it misses the mutant about once in 700 runs.

The lines they changed, by class; a line appears once for each mutant.

Needs a test, now tested:

- `internal/oidc/authorize.go`: 209, 255, 274, 279, 295, 431, 624, 702, 702,
  703
- `internal/oidc/claims.go`: 222, 231, 233, 233, 234
- `internal/oidc/cors.go`: 110
- `internal/oidc/formpost.go`: 65
- `internal/oidc/issuer.go`: 49, 81
- `internal/oidc/logout.go`: 77, 77
- `internal/oidc/params.go`: 12, 12, 12, 12, 31, 37
- `internal/oidc/pkce.go`: 32, 32, 32
- `internal/oidc/revocation.go`: 135, 141
- `internal/oidc/token.go`: 116, 116, 117, 117, 247, 326
- `internal/oidc/userinfo.go`: 150, 150, 150
- `internal/registry/argon2.go`: 17, 17, 18, 18, 25, 47, 55, 55, 56, 56, 65,
  65, 65, 67, 76, 78, 81, 82, 99
- `internal/registry/registry.go`: 293, 294, 308, 308, 309, 676, 676, 721,
  721, 726, 739, 739, 739, 823, 824, 826, 850, 876, 876, 888, 903, 903, 903,
  903, 903, 937, 938, 941, 941
- `internal/signing/signing.go`: 242, 289, 308, 338, 469, 511, 530, 531, 538

Equivalent:

- `internal/oidc/assertion.go`: 88, 96, 102, 112, 116
- `internal/oidc/authorize.go`: 146, 315, 466, 496, 501, 527, 597, 624, 624,
  and one `case` body already empty
- `internal/oidc/claims.go`: one `case` body already empty
- `internal/oidc/formpost.go`: 87
- `internal/oidc/issuer.go`: 31, 47, 81
- `internal/oidc/logout.go`: 99, 245
- `internal/oidc/params.go`: 26
- `internal/oidc/pkce.go`: one `case` body already empty
- `internal/oidc/provider.go`: 38, 38
- `internal/oidc/revocation.go`: 54, 64, 88, 88, and one `case` body already
  empty
- `internal/oidc/token.go`: 116, 127, 172, 319, 324, 492, 945, 945, 945
- `internal/oidc/userinfo.go`: 109, 213, 239, and one `case` body already
  empty
- `internal/registry/argon2.go`: 54, 54, 58, 99, 103
- `internal/registry/registry.go`: 290, 293, 293, 299, 299, 312, 312, 313,
  525, 525, 610, 798, 798, 823, 883, 984, 1018, 1018, and one `case` body
  already empty
- `internal/signing/signing.go`: 246, 248, 261, 334, 375, 382, 382, 507, 527

Cannot fail:

- `internal/oidc/authorize.go`: 641, 726, 726
- `internal/oidc/claims.go`: 55, 59, 77, 87, 100, 110, 132
- `internal/oidc/discovery.go`: 127
- `internal/oidc/formpost.go`: 82, 82
- `internal/oidc/token.go`: 672, 840, 923, 948, 954, 1013, 1013
- `internal/oidc/userinfo.go`: 122, 222, 241
- `internal/signing/signing.go`: 155, 159, 163, 224, 265, 272, 276, 384,
  413, 417, 421, 494, 535, 550

Log or capacity only:

- `internal/oidc/assertion.go`: 62
- `internal/oidc/authorize.go`: 217, 225, 236, 346
- `internal/oidc/logout.go`: 255
- `internal/oidc/revocation.go`: 49
- `internal/oidc/token.go`: 87, 295, 873
- `internal/oidc/userinfo.go`: 111, 122
- `internal/registry/registry.go`: 479, 479, 479, 480, 480
- `internal/signing/signing.go`: 193, 193, 194

Database or I/O failure (#100):

- `internal/oidc/authorize.go`: 217, 218, 225, 226, 303, 303, 318, 318, 346,
  347
- `internal/oidc/logout.go`: 80, 80, 103, 103, 107, 145, 145, 161, 161, 164,
  164, 174, 256
- `internal/oidc/revocation.go`: 103, 126
- `internal/oidc/token.go`: 231, 355, 490, 496, 503, 526, 540, 543, 593,
  752, 761, 786, 789, 828
- `internal/oidc/userinfo.go`: 263, 267
- `internal/signing/signing.go`: 176, 227, 372, 394, 397, 403, 445

### 2026-11-10, gremlins

The first run, with [gremlins](https://github.com/go-gremlins/gremlins)
v0.6.0, which `make mutation` ran until #97. It mutates only positions
inside a block of Go's coverage profile, so it ran no mutant in the
condition of a `case` clause
([#298](https://github.com/go-gremlins/gremlins/issues/298)), and counts a
mutant that does not compile as killed
([#321](https://github.com/go-gremlins/gremlins/issues/321)). It ran with
`--integration --coverpkg ./...`, one worker, and every test uncached
(`GOFLAGS=-count=1`); its mutators were its defaults: arithmetic,
conditional boundaries, conditional negation, increment and decrement,
and inverted negatives.

- **Test efficacy** is killed / (killed + lived); timed-out mutants count
  in neither.
- **Mutator coverage** is (killed + lived) / (killed + lived + not covered):
  the share of mutants in code that Go's coverage profile counts as run.
- **Both scores are upper bounds**, since some killed mutants may be ones
  that did not compile.

gremlins v0.6.0, Go 1.27.3, PostgreSQL 17.2 (Postgres.app), at `dfbfa19`;
79 minutes, with no SQLSTATE 53300 in the server's log while it ran.

| Package             | Killed | Lived | Timed out | Not covered | Test efficacy | Mutator coverage |
| ------------------- | -----: | ----: | --------: | ----------: | ------------: | ---------------: |
| `internal/oidc`     |    238 |     9 |         0 |          72 |        96.36% |           77.43% |
| `internal/registry` |     94 |     9 |         1 |          48 |        91.26% |           68.21% |
| `internal/signing`  |     44 |     2 |         0 |           5 |        95.65% |           90.20% |

Of the 125 mutants not covered, 111 are conditions of `case` clauses (64 in
`internal/oidc`, 47 in `internal/registry`) and 13 are in package-level
declarations; one alone, the `Retry-After` header at
`internal/oidc/token.go:117`, is in a statement no test runs. The `case`
conditions include the PKCE checks in `internal/oidc/authorize.go` and
`pkce.go`, the checks on a private_key_jwt assertion in `assertion.go`, those
on an access token in `userinfo.go`, and the parsing of redirect URIs in
`internal/registry/registry.go`: gremlins listed their mutants but ran none of
them. Nor was any `&&` or `||` inverted, which many of the checks that were
mutated are built from.

Mutants that lived, and the one that timed out, with the line each changed.
The go-mutesting run above classifies a mutant at each of these lines.
go-mutesting has no negation, so the negation mutants were applied again
by hand after #97's tests: those at `internal/oidc/authorize.go:345` and
`logout.go:106` and `173`, which write an error after a page written
whole, and at `token.go:116`, are killed; those at `token.go:872` and
`internal/signing/signing.go:193` change only whether a line is logged,
and the one at `revocation.go:88` only the order in which the token is
looked up, which the go-mutesting mutants of that line show equivalent.

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
