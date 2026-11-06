# Harness

Every control that shapes how agents work in this repository, why it exists,
and the evidence that it helps. A control without a reason is removed; a
control whose reason is "it seemed like a good idea" is a hypothesis, and is
marked as one until an eval or a recorded incident settles it.

Controls are classified after Böckeler's harness engineering model
(<https://martinfowler.com/articles/harness-engineering.html>): **guides**
steer the agent before it acts, **sensors** check its output after;
each is **computational** (deterministic) or **inferential** (a model judges).

## How controls are added

Only when a trigger appears (Anthropic, `docs/research/ai-development.md`):

| Trigger                                | Control                         |
| -------------------------------------- | ------------------------------- |
| The same mistake twice                 | A line in `AGENTS.md`           |
| The same procedure prompted repeatedly | A skill, written after its eval |
| Side-task output floods the session    | A subagent                      |
| It must happen every time              | A hook or a gate                |
| A second repository needs it           | A plugin                        |

Every addition gets a row below and an entry in the changelog naming what
justified it: an incident, an eval, a review finding or the maintainer's
decision. A custom skill, subagent or hook needs more: a recorded failure
and an eval that can measure it (`AGENTS.md`, "Deliberately not doing"). One
departure: `right-sizing` became a plugin before a second repository needed
it, because `claude plugin eval` evaluates only plugins.

## Controls

| Control                                              | Kind                  | Why                                                                                                                                                                                                                                                                                                                                                                                      | Evidence                                                                                                                                                                                                                  |
| ---------------------------------------------------- | --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AGENTS.md` (imported by `CLAUDE.md`)                | Guide, inferential    | What an agent cannot discover from the code: authorities, conventions, what not to build                                                                                                                                                                                                                                                                                                 | Hypothesis                                                                                                                                                                                                                |
| Sandbox (`.claude/settings.json`)                    | Guide, computational  | The primary local control: writes and network are confined at the OS level. Apart from the commands listed under Deliberate weakenings, Claude cannot leave it (`allowUnsandboxedCommands: false`)                                                                                                                                                                                       | Hypothesis                                                                                                                                                                                                                |
| Permission rules                                     | Guide, computational  | Deny secrets; ask before `git push`; allow read-only `gh` commands, which run outside the sandbox and so are not auto-allowed as sandboxed commands are. Bash argument patterns are hints, not enforcement: `git push -f` evades the force-push deny but is still caught by the `git push` ask; `git commit -n` evades the `--no-verify` deny entirely, which is why CI rechecks commits | Hypothesis                                                                                                                                                                                                                |
| PostToolUse `format.sh`                              | Sensor, computational | Formatting never reaches a gate or a reviewer; Go via golangci-lint, Markdown, YAML and JSON via Prettier, Markdown also via markdownlint, shell via shfmt, one file at a time                                                                                                                                                                                                           | Hypothesis                                                                                                                                                                                                                |
| Prettier and `markdownlint-cli2` in `make check`     | Sensor, computational | Documents are a primary output here; Prettier formats, markdownlint lints what formatting cannot decide                                                                                                                                                                                                                                                                                  | Incident: editor and gate disagreed                                                                                                                                                                                       |
| `make setup` / `make tools`                          | Guide, computational  | One definition of the toolchain for a fresh machine and for CI; every tool pinned                                                                                                                                                                                                                                                                                                        | Hypothesis                                                                                                                                                                                                                |
| `shellcheck` and `shfmt` in `make check`             | Sensor, computational | The harness is itself code; its scripts get the same scrutiny as Go                                                                                                                                                                                                                                                                                                                      | Hypothesis                                                                                                                                                                                                                |
| `zizmor` in `make check` (`make workflow-check`)     | Sensor, computational | Agent workflows are the first here to handle a secret and untrusted pull request text; zizmor finds template injection, over-broad permissions and unpinned or impostor actions before they merge. Offline in `make check`; CI also runs its online audits, with a read-only token                                                                                                       | Hypothesis                                                                                                                                                                                                                |
| `misspell -locale US` in `make check` (`make spell`) | Sensor, computational | American English in prose and config, which golangci-lint's misspell does not read. It catches common British spellings, not every one ("judgement" passes)                                                                                                                                                                                                                              | Incident: an audit found British spellings in two documents that no gate had checked                                                                                                                                      |
| Stop `stop-check.sh` → `make check`                  | Sensor, computational | An agent may not finish on a red gate; reported once per tree so it cannot loop. Tested in `internal/harness`. Since #12 the gate's tests need a running PostgreSQL, named by `PULSAR_TEST_DATABASE_URL` in the environment Claude Code starts with; without either, they fail, and so does the hook                                                                                     | Incident: silent fingerprint failure                                                                                                                                                                                      |
| `make check` / `make verify`                         | Sensor, computational | The objective definition of done                                                                                                                                                                                                                                                                                                                                                         | Hypothesis                                                                                                                                                                                                                |
| `main` ruleset                                       | Sensor, computational | Where enforcement actually lives: a pull request is required, `make verify`, `make conformance` and Conventional Commits must pass on an up-to-date branch, review threads must be resolved, and force pushes and deletion are blocked, with no bypass                                                                                                                                   | Hypothesis                                                                                                                                                                                                                |
| `repocheck`                                          | Sensor, computational | Every requirement has a test, so removing a requirement's last test fails the gate; TODOs name issues. Active on requirements since #14 added the first ones                                                                                                                                                                                                                             | Hypothesis                                                                                                                                                                                                                |
| `sqlc diff` in `make check` (`make sqlc-check`)      | Sensor, computational | Query code is generated by sqlc and committed; the gate fails when it differs from what `sqlc.yaml`, the `queries.sql` files and the migrations generate                                                                                                                                                                                                                                 | Maintainer's decision (#13)                                                                                                                                                                                               |
| `make dockerfile-check` in `make check`              | Sensor, computational | The golang image pins `GOTOOLCHAIN=local`, so `Dockerfile` builds only with the Go release `go.mod` names, and `make verify` never builds it; the gate fails when the two differ, rather than the conformance job                                                                                                                                                                        | Review finding (#15)                                                                                                                                                                                                      |
| `make conformance` and its CI job                    | Sensor, computational | The external oracle of #11: the OpenID Foundation's conformance suite checks pulsar over the wire, outside `go test`; the Config OP plan for now. A warning fails it as a failure does, unless an entry in `conformance/` accepts it with a reason                                                                                                                                       | Maintainer's decision (#11)                                                                                                                                                                                               |
| `golangci-lint` configuration                        | Sensor, computational | Rules a tool can decide live in the tool, not in prose                                                                                                                                                                                                                                                                                                                                   | Hypothesis                                                                                                                                                                                                                |
| Conventional Commits hook and CI job                 | Sensor, computational | One commit format, checked locally and in CI from one script; Dependabot's pull requests get its case and lengths (Versions)                                                                                                                                                                                                                                                             | Hypothesis                                                                                                                                                                                                                |
| `mattpocock-skills:code-review` (spec axis)          | Sensor, inferential   | Fresh-context review of the diff against the spec; step 1 of "Before a pull request" in `AGENTS.md`                                                                                                                                                                                                                                                                                      | Pending ablation                                                                                                                                                                                                          |
| `/security-review` before a PR                       | Sensor, inferential   | Anthropic runs it on its own pull requests; step 2 in `AGENTS.md`                                                                                                                                                                                                                                                                                                                        | Pending ablation                                                                                                                                                                                                          |
| `code-review@claude-plugins-official` on PRs         | Sensor, inferential   | Parallel reviewers, each finding validated separately; step 3 in `AGENTS.md`, run locally until CI runs it (#1)                                                                                                                                                                                                                                                                          | Pending ablation                                                                                                                                                                                                          |
| `right-sizing` skill (`plugins/right-sizing/`)       | Guide, inferential    | Asked a decision plainly, models answered from training data without researching; the skill makes them fetch dated primary sources, size the decision and record the research. Enabled from `main` through this repository's own marketplace (`.claude-plugin/marketplace.json`), so sessions use the released version, not the working copy                                             | Eval of 0.2.0: research graders 0/48 → 48/48 on Sonnet and Opus, fired on 18/18 decision questions and 0/9 non-decisions, no regression, about 4.5× estimated cost per decision (`plugins/right-sizing/evals/results.md`) |
| The maintainer merges every pull request             | Sensor, inferential   | Auth is where unsupervised agents are least trusted                                                                                                                                                                                                                                                                                                                                      | —                                                                                                                                                                                                                         |

The three review controls are kept only if the ablation shows each one finds
problems the others miss.

**Solo-maintainer exception.** GitHub does not let a pull request's author
approve it, and agents here act through the maintainer's own account, so the
ruleset cannot require an approving review. Human review is the maintainer
reading and merging each pull request; the ruleset guarantees that nothing
reaches `main` any other way. This holds until there is a second reviewer or
agents get an identity of their own.

## Deliberate weakenings

Each loosening of the sandbox, and the need that forced it:

- **`enableWeakerNetworkIsolation: true`.** Without it, Go's TLS
  verification fails under macOS Seatbelt (`x509: OSStatus -26276`), so no
  module can be downloaded; tested 2026-11-05, with the egress proxy a plain
  CONNECT tunnel (certificates not re-signed). This is outside the documented
  purpose, a MITM proxy with a custom CA; the documented fix for Go tools
  failing TLS on macOS is `excludedCommands`, which would take every `go`
  command out of the sandbox. The cost: a potential exfiltration path through
  the macOS trust service.
- **`excludedCommands`: `gh *`, `git push *`.** They need the maintainer's
  GitHub credentials, which never enter the sandbox. `git push` still asks
  first; read-only `gh` commands in the allow list do not.
- **`excludedCommands`: `docker compose *`.** The conformance suite runs in
  Docker Compose (#15), and inside the sandbox a command cannot reach the
  Docker daemon's socket (`connect: operation not permitted`, observed
  2026-11-06). Outside it, nothing confines what Compose does: a compose
  file can bind-mount any host path into a container, so this exclusion
  reaches every file an agent could write a compose file to mount. No allow
  rule matches it, so each such command asks first. The exclusion matches
  the command as written: `make conformance`, or `docker compose` behind a
  `VAR=value` prefix, still runs inside the sandbox and fails there, so the
  maintainer runs `make conformance`. The setting is read when a session
  starts.
- **`network.allowLocalBinding: true`.** Tests start servers on loopback.
- **`filesystem.allowWrite`: `~/go` and the Go and golangci-lint caches.**
  The Go toolchain and the linter write their module and build caches there.
  `~/go/bin` is one place a planted executable could land.
- **`network.allowedDomains`: `proxy.golang.org`, `sum.golang.org`,
  `vuln.go.dev`.** Module downloads, checksum verification and govulncheck's
  vulnerability database.
- **Hooks run outside the sandbox.** Claude Code runs hooks with the
  maintainer's permissions, and both hooks execute files agents can edit:
  - The Stop hook runs `make check`, which executes the Makefile and every Go
    test, so code an agent writes runs unsandboxed, with full network, the
    next time it stops. Observed 2026-11-05, when the Stop hook downloaded
    golangci-lint from GitHub, which the sandbox cannot reach.
  - The format hook, after every edit, evaluates the Makefile (running any
    `$(shell …)` in it) and runs the executables in `bin/` and
    `node_modules/.bin/`, all writable by agents. The same risk, more often.

  Accepted for now because these hooks are the harness's main sensors; the
  change that closes the gap is running them inside the sandbox, and it waits
  for a measured need. Reading every pull request before it merges protects
  `main`, not the machine: by the time a pull request is read, the hooks have
  already run.

## The test database

The gate's tests need a real PostgreSQL (#11, Testing Decisions). Two
consequences follow; neither is a sandbox setting.

- **What sandboxed code reaches.** Sandboxed tests reached Postgres.app on
  `localhost:5432` with no setting of their own (observed 2026-11-05). The
  role in `PULSAR_TEST_DATABASE_URL` needs `CREATEDB`, and an agent can use
  it on every database that role may open on that server, not only the
  test databases; a role used for nothing but these tests limits that.
- **What the tests leave behind.** Each test's database is dropped when the
  test ends, unless its test binary is killed first. Template databases,
  `pulsar_template_<hash>`, are kept between runs, one per distinct set of
  migrations, so they accumulate as migrations change. While no tests run,
  list what is left and drop what is not wanted:

  ```sh
  psql "$PULSAR_TEST_DATABASE_URL" -Atc \
    "SELECT datname FROM pg_database WHERE datname LIKE 'pulsar\_template\_%' OR datname LIKE 'pulsar\_test\_%'"
  psql "$PULSAR_TEST_DATABASE_URL" -c 'DROP DATABASE pulsar_template_<hash> WITH (FORCE)'
  ```

  A template dropped this way is rebuilt by the next test that needs it.

## Versions

The official marketplace is frozen with `"autoUpdate": false`: plugins stay
at whatever version was last installed, which is not a pin to a recorded
version, and change only when updated on purpose, with a changelog entry.
This repository's own marketplace, `pulsar`, does update itself: it only ever
moves to what has merged on `main`, and a plugin's new version takes effect
when its `version` is bumped, which makes the bump the release. Every eval
result and ExecPlan outcome records the Claude Code version, model IDs and
the commits on `main` it ran against; `make eval` sets
`DISABLE_AUTOUPDATER=1` so Claude Code cannot update during a run.
`GOLANGCI_LINT_VERSION`, `SHELLCHECK_VERSION` and `ZIZMOR_VERSION` in the
Makefile are invisible to Dependabot and are bumped by hand. CI's
PostgreSQL service image, pinned by tag and digest in
`.github/workflows/ci.yml`, is bumped by hand too, and so are the images
of the conformance stack, pinned the same way in `Dockerfile`,
`conformance/compose.yaml` and `conformance/runner/Dockerfile`. The suite's
images and its runner scripts move together: the scripts are fetched from
the commit that the images' release tags, each verified by its sha256, and
the runner's Python packages are pinned by hash in
`conformance/runner/requirements.txt`; both are bumped by hand. So are the
Node tools: Dependabot raises alerts from `pnpm-lock.yaml` but cannot update
a pnpm 12 lockfile. Its first security updates, on 2026-11-05, failed with
"VulnerabilityAuditor: missing lockfile".

A vulnerable transitive dependency is patched with an override in
`pnpm-workspace.yaml` when its fixed version is in range, with the advisory
and the condition for removing the override beside it. When the vulnerable
code is not reachable from how the tool is used, the alert is dismissed as
"vulnerable code not actually used", with the evidence in the dismissal.

Dependabot's commits are checked with `scripts/check-commit-msg.sh
--dependabot`, which CI passes only for pull requests that `dependabot[bot]`
opened. That mode still requires a known type and no trailing period, but
allows a capitalized first word and a header past 72 characters, so
Dependabot's commits can land on `main` as `build: Bump <module> from
<version> to <version>`. Neither can be configured. Dependabot capitalizes
when every recent human commit in the 100 it reads has a colon followed by
a capital somewhere in its message, which the `Co-Authored-By: Claude`
trailer gives every commit here, unless the most recent Dependabot commit
among those 100 sets the case instead. With dozens of commits a day, its
own commits leave that window before its next weekly run. Module paths
with pseudo-versions exceed 72 characters in any case. Read from
dependabot-core's
[`PrNamePrefixer`](https://github.com/dependabot/dependabot-core/blob/0e024a6d20eaa5b8728f5cfe3b9c340a35145663/common/lib/dependabot/pull_request_creator/pr_name_prefixer.rb#L78-L85)
at `0e024a6`.

Tools are installed by the maintainer, outside the sandbox, with `make setup`.
Inside it, pnpm cannot switch to the version `package.json` pins (it fails to
take a store lock), and the release binaries come from GitHub, which the
sandbox does not reach. Agents only run tools already installed.

## Removed

None yet.

## Changelog

- Initial harness: the controls above, chosen from the research in
  `docs/research/ai-development.md`. All are hypotheses until measured.
- Added Markdown linting to the gate and the format hook after the editor
  reported markdownlint warnings that `make check` did not.
- Moved pinned Go tools from `go.tool.mod` to `tools/go.mod`: Dependabot
  cannot see a modfile that is not a module directory, so the tools were
  never going to be updated.
- Stop hook: fingerprinting failed silently when a temporary file could not
  be created, which cached a fixed "pass". It now keeps its scratch index in
  the git directory and, if it still cannot fingerprint, checks every time.
- From an audit of the harness by a separate Claude session that had not
  written it (same model), with each external claim then checked against its
  primary source:
  - Added the `main` ruleset; until then the gates were advisory.
  - Restated permission rules as hints; the ruleset and CI are enforcement.
  - The format hook linted and fixed every Markdown file on each edit; it now
    passes `--no-globs` and touches only the edited file.
  - markdownlint ran through `npx` with no lockfile, so its dependencies
    resolved at run time. It was then pinned by `package-lock.json`, later
    replaced by pnpm (below).
  - Added `shellcheck` and `shfmt` over the harness scripts, and tests for the
    Stop hook's pass, fail-once and unfingerprintable paths.
  - Set `allowUnsandboxedCommands: false`, kept `enableWeakerNetworkIsolation`
    after testing showed Go needs it, and documented every weakening.
  - Froze the plugin marketplace with `"autoUpdate": false`.
- Maintainer's decision, after research: replaced npm with pnpm for its
  default supply-chain protections, and added Prettier: markdownlint is a
  linter, and the most widely adopted formatter for Markdown, YAML and JSON
  is Prettier.
- Maintainer's request that a fresh clone set itself up: added `make setup`
  and `make tools`. Release binaries now install into
  `./bin` under versioned names, golangci-lint verified against its published
  checksums, and CI calls the same targets instead of its own install steps.
- The format hook names `make setup` when a tool is missing, instead of
  failing with "No such file or directory".
- From a second review of the harness:
  - ShellCheck's archive is now verified against a pinned sha256, as
    golangci-lint's already was; the installed binary was compared and
    matched the verified release.
  - Dependabot waits a seven-day cooldown before proposing version updates,
    so a compromised release has time to be caught first.
  - Recorded that the format hook, like the Stop hook, runs agent-writable
    files outside the sandbox.
  - Trimmed the allow list to read-only `gh` commands; the rest were
    redundant with `autoAllowBashIfSandboxed`, and the `golangci-lint`
    patterns never matched the versioned binary in `bin/`.
  - CI's Go cache is keyed on `tools/go.sum` as well as `go.sum`, so the
    pinned tools are no longer downloaded on every run.
  - The format hook now runs shfmt on shell scripts, as the gate checks them,
    and stops with a blocking error when jq is missing instead of failing
    silently; jq is listed as a prerequisite.
- Node tools are reinstalled when the content of `package.json` or
  `pnpm-lock.yaml` changes, not their timestamps. A git checkout rewrote the
  timestamps, the gate tried to reinstall inside the sandbox, and failed.
- markdownlint's rules moved into `.markdownlint.jsonc`, which a directory's
  own config extends. A nearer config replaces the root one rather than
  merging with it: a directory that relaxed one rule silently re-enabled the
  rest, and the format hook turned the tabs in a Go code block into spaces.
- Added the `right-sizing` skill, the first custom control, written after
  baseline evals showed the gap it closes and kept on the strength of its
  with-and-without results. A review caught that it was evaluated but never
  enabled; the repository is now its own marketplace, and the skill is
  enabled in `.claude/settings.json` from `main`.
- The Conventional Commits check moved to its own workflow, triggered also
  when a pull request is edited. A title that failed the check could not be
  fixed: editing it ran nothing, and a rerun replays the original title.
- Dependabot cannot update a pnpm 12 lockfile, as first observed when it
  failed to patch two alerts. re2js is patched with a pnpm override; the
  katex alert is dismissed because markdownlint never loads the code that
  calls katex.
- From a full audit of every file by an agent that had written none of them:
  eval results cited commit SHAs that a rebase merge had rewritten; updates
  were said to be frozen during evals but `make eval` did not freeze them;
  two sandbox loosenings were unlisted, and one of them,
  `storage.googleapis.com`, had no recorded need and was removed; the commit
  check let "feat: A new endpoint" through, now fixed and tested; and a dozen
  descriptions said more than the files did. Dependabot's npm entry was
  dropped, since it can only fail.
- From a final audit before leaving the bootstrap phase, by another agent
  that had written none of it:
  - The three review controls were listed but nothing told an agent to run
    them; `AGENTS.md` now has a "Before a pull request" section.
  - Added `make spell`: the audit before it had found British spellings in
    documents that no gate checked.
  - Node tools now reinstall when `pnpm-workspace.yaml` changes; an override
    edited alone could have passed locally and failed in CI. The changed
    fingerprint makes every existing clone reinstall once, which the sandbox
    cannot do: after this lands, run `make tools` outside it.
  - Dropped the `docker compose *` sandbox exclusion until the conformance
    suite needs it (#2).
  - The near-miss eval case is cited at the commit that added it, a cost was
    rounded wrongly, and several changelog entries now name what justified
    them.
- Maintainer's decision, and a step toward #1: added zizmor to
  `make workflow-check`, installed as a release binary verified against a
  pinned sha256, as ShellCheck is. #1 planned `zizmorcore/zizmor-action`
  instead; the Makefile keeps one definition of the toolchain, so the Stop
  hook and CI run the same target. Elsewhere zizmor runs offline; CI runs it
  a second time, in a step of its own, with a read-only token for its online
  audits. Those audits can fail CI without any change here, when an advisory
  is published for a pinned action; that is intended. The review workflow's
  write permissions moved from the workflow to its job, as zizmor's
  `excessive-permissions` remediation recommends. Existing clones run
  `make tools` once, outside the sandbox, to install zizmor.
- The spec's testing decisions (#11), implemented in #12: tests run against
  a real PostgreSQL named by `PULSAR_TEST_DATABASE_URL`, and fail, not skip,
  when it is unset, so a gate without a database cannot pass by testing
  less. The Stop hook's `make check` therefore needs PostgreSQL running and
  the variable set where Claude Code starts. A missing database fails the
  hook like any red gate, reported once per tree, so it cannot trap an
  agent; the hook's own tests fake `make` and need no database. CI runs
  PostgreSQL as a service container, pinned by digest.
- Maintainer's decision, in #13: sqlc v1.31.1 is pinned in `tools/go.mod`
  and `make check` runs `sqlc diff`, so committed query code cannot drift
  from the queries and migrations it is generated from. `make sqlc`
  regenerates it. This version parses SQL with a WebAssembly build of
  PostgreSQL's parser, so it builds without cgo.
- The spec's conformance decisions (#11), implemented in #15:
  `make conformance` runs the suite's Config OP plan against pulsar in
  Docker Compose, and a CI job of its own runs the same target on every
  pull request and uploads the exported results. The `docker compose *`
  sandbox exclusion, dropped until the suite needed it, is restored. It
  does not cover `make conformance` itself, which the maintainer runs.
  From the pull request's review: `make check` now fails when the
  Dockerfile's Go release differs from `go.mod`'s, which only the
  conformance job would otherwise have found.
  Maintainer's decision: the `main` ruleset requires `make conformance`,
  so a regression in conformance blocks a merge (#11, story 72).
- Dependabot's first pull requests, #30 and #31, failed the Conventional
  Commits check with `build: Bump …`. Their commits landed in #33 with the
  first word lowercased by hand, and the check gained `--dependabot` for
  pull requests Dependabot opens, so the next ones pass as written
  (Versions, above). Lowercasing alone would not have lasted: Dependabot
  copies its own last commit only while that commit is among `main`'s 100
  most recent.
