# Mutation testing tools for Go

Surveyed 2026-11-11. Context: one maintainer measuring the strength of the
tests of three security-critical packages, `internal/oidc`,
`internal/registry` and `internal/signing`, whose checks are mostly
conditions joined by `&&` and `||`, many of them in `case` clauses. It is a
measurement run by hand, not a gate (#5), so a run of hours is acceptable;
what matters is that every check is measured and that every status is
true. The tests use one shared PostgreSQL, so mutants run one at a time.
Follows the first run with gremlins (`docs/mutation-testing.md`) and #97.

## Findings

### Practice

- Google runs mutation testing on the code a change touches, at code
  review, in ten languages including Go, with five operators: arithmetic
  replacement (AOR), logical connector replacement (LCR: `a && b` becomes
  `a || b`, `true`, `false`, `a` or `b`), relational replacement (ROR),
  unary insertion (UOI) and statement block removal (SBR).
  [Practical Mutation Testing at Scale: A view from Google](https://ar5iv.labs.arxiv.org/html/2102.11378),
  §II-B, IEEE TSE 2021, accessed 2026-11-11, primary.
- It marks "arid" nodes and does not mutate them: calls to functions whose
  name starts with `log`, sleeps and deadlines, capacity hints. Developers
  first rated 85% of mutants unproductive; suppressing these, mostly
  logging, timing and configuration flags, raised the productive share to
  89%. Same source, §I and §III.
- It does not aim to kill every mutant: a developer marks each one surfaced
  "Please Fix" or "Not useful". Same source, §II-D.
- Thoughtworks Technology Radar Vol. 35 puts mutation testing in Adopt, as a
  guardrail for tests written by AI, and advises targeting packages because
  full runs are slow (`docs/research/evals.md`, "Issue #5"). It names no Go
  tool.
- No Go tool is a standard: the Go project ships none, and the candidates
  below are each maintained by one person or one team.

### Candidates

| Tool                                                                  | Stars | Last commit | Last release       | Notes                                         |
| --------------------------------------------------------------------- | ----: | ----------- | ------------------ | --------------------------------------------- |
| [go-gremlins/gremlins](https://github.com/go-gremlins/gremlins)       |   463 | 2026-03-30  | v0.6.0, 2025-12-06 | The first run's tool                          |
| [avito-tech/go-mutesting](https://github.com/avito-tech/go-mutesting) |   283 | 2026-10-02  | v2.3.1, 2025-12-26 | A fork of zimmski/go-mutesting, kept by Avito |
| [gtramontina/ooze](https://github.com/gtramontina/ooze)               |   290 | 2026-08-19  | v0.3.1 tag         | A library, run from a test behind a build tag |
| [zimmski/go-mutesting](https://github.com/zimmski/go-mutesting)       |   679 | 2024-07-04  | v1.2, 2021-06-10   | Unmaintained; the original of Avito's fork    |
| gomutants, gomutant, ditto and other forks                            |  < 20 | 2026        | —                  | Created in 2026; too young to rely on         |

Counts from the GitHub API, 2026-11-11, primary.

- **gremlins** mutates only positions inside a block of Go's coverage
  profile, so it never runs a mutant in the condition of a `case` clause;
  reported upstream as
  [#298](https://github.com/go-gremlins/gremlins/issues/298) (opened
  2026-07-16, reproduced by two others, no maintainer reply by 2026-11-11).
  It counts a mutant that does not compile as killed, because `go test`
  exits 1 for a build failure as for a failing test
  ([#321](https://github.com/go-gremlins/gremlins/issues/321), opened
  2026-10-09; a fix waits in PR #283). In integration mode it ran cached
  test results unless `-count=1` is set
  ([#272](https://github.com/go-gremlins/gremlins/issues/272)); the first
  run set it. Its operators are replacements only: boundary, negation,
  arithmetic, increment, and optionally `&&`↔`||`; it removes no statement.
  Its README says it is in 0.x and slow on large modules. Primary.
- **avito-tech/go-mutesting** runs every mutant, covered or not. Its
  operators include statement removal and the emptying of `if`, `else` and
  `case` bodies (Google's SBR), replacing each term of an `&&` or `||` with
  `true` or `false` (most of LCR), boundary changes, arithmetic, and integer
  increments; its README, read 2026-11-11, primary. Its negation mutator
  (`==`↔`!=`, `<`↔`>=`) is written but not registered in the binary
  ([#55](https://github.com/avito-tech/go-mutesting/issues/55), open since
  2026-05-24, with a one-line fix in #56 unmerged). It writes each mutant
  over the source file and restores it afterwards, and its built-in exec
  runs only the mutated package's tests and reads `go test`'s exit code 1
  as killed, whether the tests failed, the build failed or a test timed out
  (`cmd/go-mutesting/main.go` at `9ce5f73`, read 2026-11-11, primary).
  An external exec command replaces the built-in one and decides each
  status itself. Avito merges its own changes, the last on 2026-10-02 for
  Go 1.27; the outside pull requests opened since May 2026 are open or were
  closed unmerged.
- **ooze** copies the repository to a temporary directory for each mutant
  (`internal/fsrepository` at `87c15dc`), so the working tree is never
  changed. Its operators cover comparison boundaries and negation
  (`==`↔`!=`), replacing a term of `&&` or `||`, arithmetic, bitwise,
  integer increments and loops; it removes no statement or branch. It is
  run as a test that imports it, so it would be a dependency of a test
  module, and it prints its results instead of writing a machine-readable
  report. Its [readme](https://github.com/gtramontina/ooze), read
  2026-11-11, primary. Whether it skips uncovered code was not checked.
  UNVERIFIED.
- One team comparing the same three tools for its CI chose gremlins as the
  primary tool with Avito's go-mutesting as a cross-check, ruling out ooze
  and the original go-mutesting
  ([Backblaze/blazer#97](https://github.com/Backblaze/blazer/issues/97),
  2026-10-06, secondary): it runs on pull requests and needs a diff mode,
  which pulsar does not.

### Measured here

On `validPKCEValue` alone (`internal/oidc/pkce.go`), go-mutesting ran 20
mutants in 304 seconds; 3 lived, each replacing one bound of a character
range in a `case` condition with `true`, which no test notices. gremlins
listed that condition's mutants as not covered and ran none.

Over the three packages, on the same code as gremlins' run of 2026-11-10,
go-mutesting through `scripts/mutation-exec.sh` ran all 1,366 mutants in 5
hours 41 minutes, against gremlins' 397 run, 125 not run, in 79 minutes; 224
did not compile and were skipped. 280 lived, against gremlins' 20, and at
every line where a gremlins mutant lived, one lived here too, on that line
or in the body of the `if` it begins. Six killed mutants drawn at random
were run again by hand: each failed tests of the behavior it changed. The
run and the class of each mutant that lived are in
`docs/mutation-testing.md`.

## Decision

avito-tech/go-mutesting, pinned by commit in `tools/go.mod`, run through
`scripts/mutation-exec.sh`, replaces gremlins, which is removed; the full
run confirmed what the run on `validPKCEValue` showed.

It is the only candidate that measures every check #5 names: it runs the
`case` conditions gremlins skips, and it has the two operators Google
reports as productive that gremlins lacks, statement block removal and
replacing a logical term. Its defects are each answered outside it: the
exec script runs every package's tests, builds the mutant first so that
one that does not compile is skipped rather than killed, and reports
timeouts and a full database apart from kills; a working tree of its own
holds the file it rewrites. What is left is the missing negation of
comparisons, which neither the exec nor the configuration can add; at each
line where a gremlins negation mutant lived, a go-mutesting mutant lived
too. The cost is time: almost six hours, against 79 minutes, for more than
three times the mutants.

Rejected: gremlins, which cannot run the `case` conditions and counts
mutants that do not compile as killed, until #298 and #321 are fixed in a
release. ooze, which removes no statements and reports no machine-readable
results, though it is the safest of the three to run. The original
go-mutesting, unmaintained. The tools created in 2026, too young.

Mutants in logging calls follow Google's arid nodes: one whose only effect
is whether a line is logged is recorded, not tested.

Revisit when go-mutesting registers its negation mutator or stops
merging changes, when gremlins releases fixes for #298 and #321, or when
ooze gains statement removal; or if mutation testing moves into a gate,
where a diff mode and run time would decide.
