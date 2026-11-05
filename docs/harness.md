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

Every addition gets a row below and an entry in the changelog naming the
incident or eval that justified it.

## Controls

| Control                                          | Kind                  | Why                                                                                                                                                                                                                                                                                                                                                                                      | Evidence                             |
| ------------------------------------------------ | --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| `AGENTS.md` (imported by `CLAUDE.md`)            | Guide, inferential    | What an agent cannot discover from the code: authorities, conventions, what not to build                                                                                                                                                                                                                                                                                                 | Hypothesis                           |
| Sandbox (`.claude/settings.json`)                | Guide, computational  | The primary local control: writes and network are confined at the OS level. Apart from the commands listed under Deliberate weakenings, Claude cannot leave it (`allowUnsandboxedCommands: false`)                                                                                                                                                                                       | Hypothesis                           |
| Permission rules                                 | Guide, computational  | Deny secrets; ask before `git push`; allow read-only `gh` commands, which run outside the sandbox and so are not auto-allowed as sandboxed commands are. Bash argument patterns are hints, not enforcement: `git push -f` evades the force-push deny but is still caught by the `git push` ask; `git commit -n` evades the `--no-verify` deny entirely, which is why CI rechecks commits | Hypothesis                           |
| PostToolUse `format.sh`                          | Sensor, computational | Formatting never reaches a gate or a reviewer; Go via golangci-lint, Markdown, YAML and JSON via Prettier, Markdown also via markdownlint, one file at a time                                                                                                                                                                                                                            | Hypothesis                           |
| Prettier and `markdownlint-cli2` in `make check` | Sensor, computational | Documents are a primary output here; Prettier formats, markdownlint lints what formatting cannot decide                                                                                                                                                                                                                                                                                  | Incident: editor and gate disagreed  |
| `make setup` / `make tools`                      | Guide, computational  | One definition of the toolchain for a fresh machine and for CI; every tool pinned                                                                                                                                                                                                                                                                                                        | Hypothesis                           |
| `shellcheck` and `shfmt` in `make check`         | Sensor, computational | The harness is itself code; its scripts get the same scrutiny as Go                                                                                                                                                                                                                                                                                                                      | Hypothesis                           |
| Stop `stop-check.sh` → `make check`              | Sensor, computational | An agent may not finish on a red gate; reported once per tree so it cannot loop. Tested in `internal/harness`                                                                                                                                                                                                                                                                            | Incident: silent fingerprint failure |
| `make check` / `make verify`                     | Sensor, computational | The objective definition of done                                                                                                                                                                                                                                                                                                                                                         | Hypothesis                           |
| `main` ruleset                                   | Sensor, computational | Where enforcement actually lives: a pull request is required, `make verify` and Conventional Commits must pass on an up-to-date branch, review threads must be resolved, and force pushes and deletion are blocked, with no bypass                                                                                                                                                       | Hypothesis                           |
| `repocheck`                                      | Sensor, computational | Every requirement has a test; tests cannot quietly disappear; TODOs name issues                                                                                                                                                                                                                                                                                                          | Hypothesis                           |
| `golangci-lint` configuration                    | Sensor, computational | Rules a tool can decide live in the tool, not in prose                                                                                                                                                                                                                                                                                                                                   | Hypothesis                           |
| Conventional Commits hook and CI job             | Sensor, computational | One commit format, checked locally and in CI from one script                                                                                                                                                                                                                                                                                                                             | Hypothesis                           |
| `mattpocock-skills:code-review` (spec axis)      | Sensor, inferential   | Fresh-context review of the diff against the spec                                                                                                                                                                                                                                                                                                                                        | Pending ablation                     |
| `/security-review` before a PR                   | Sensor, inferential   | Anthropic runs it on its own pull requests                                                                                                                                                                                                                                                                                                                                               | Pending ablation                     |
| `code-review@claude-plugins-official` on PRs     | Sensor, inferential   | Parallel reviewers, each finding validated separately                                                                                                                                                                                                                                                                                                                                    | Pending ablation                     |
| The maintainer merges every pull request         | Sensor, inferential   | Auth is where unsupervised agents are least trusted                                                                                                                                                                                                                                                                                                                                      | —                                    |

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
- **`excludedCommands`: `docker compose *`.** Docker cannot run inside the
  sandbox; needed for the conformance suite (#2).
- **`network.allowLocalBinding: true`.** Tests start servers on loopback.
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

## Versions

The official marketplace is pinned with `"autoUpdate": false`; plugins change
only when updated on purpose, with a changelog entry. Every eval result and
ExecPlan outcome records the Claude Code version, model IDs and plugin commit
SHAs, and Claude Code's own updates are frozen (`DISABLE_AUTOUPDATER=1`)
while a comparison runs. `GOLANGCI_LINT_VERSION` and `SHELLCHECK_VERSION` in
the Makefile are invisible to Dependabot and are bumped by hand. Dependabot's
support for pnpm v11 and later lockfiles is contested; if its first npm
update fails, the Node tools are bumped by hand too.

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
    resolved at run time. It is now pinned by `package-lock.json` and updated
    by Dependabot.
  - Added `shellcheck` and `shfmt` over the harness scripts, and tests for the
    Stop hook's pass, fail-once and unfingerprintable paths.
  - Set `allowUnsandboxedCommands: false`, kept `enableWeakerNetworkIsolation`
    after testing showed Go needs it, and documented every weakening.
  - Pinned the plugin marketplace with `"autoUpdate": false`.
- Replaced npm with pnpm for its default supply-chain protections, and added
  Prettier: markdownlint is a linter, and the most widely adopted formatter
  for Markdown, YAML and JSON is Prettier.
- Added `make setup` and `make tools`: release binaries now install into
  `./bin` under versioned names, golangci-lint verified against its published
  checksums, and CI calls the same targets instead of its own install steps.
- The format hook names `make setup` when a tool is missing, instead of
  failing with "No such file or directory".
- From a second review of the harness:
  - ShellCheck's archive is now verified against a pinned sha256, as
    golangci-lint's already was; the installed binary was compared and
    matched the verified release.
  - Dependabot waits a seven-day cooldown before proposing version updates.
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
