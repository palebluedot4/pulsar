# AGENTS.md

pulsar is an OpenID Provider in Go. The provider is the artifact; the subject
is the method: agents build it, under a harness that has to prove it helps.
Output is reviewed as if a person wrote it, by a person who will have to
explain every line.

This file is a map. Detail lives where it is linked.

## Commands

| Command            | What it does                                                                                                                                                                                                                              |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `make check`       | Tidy, stale generated query code, lint and formatting, spelling, requirement traceability, workflow lint, tests against PostgreSQL at `PULSAR_TEST_DATABASE_URL`. Runs when an agent stops, unless that working tree was already checked. |
| `make verify`      | `check`, plus reachable vulnerabilities and a build. CI runs this.                                                                                                                                                                        |
| `make fmt`         | Formats Go, Markdown, YAML, JSON and shell in place.                                                                                                                                                                                      |
| `make conformance` | The OpenID conformance suite's Config OP and Basic OP plans against pulsar, in Docker Compose. CI runs it too. It cannot reach Docker inside the sandbox; ask the maintainer to run it.                                                   |

Work is not done until `make verify` passes. Run `make help` for the rest.
Tools are installed by `make setup`, which the maintainer runs outside the
sandbox; if one is missing, say so rather than installing it.

## Where things live

| Path                           | Contents                                                                                            |
| ------------------------------ | --------------------------------------------------------------------------------------------------- |
| `cmd/pulsar/`                  | `main` and `run`; wiring, signals, shutdown. Tests drive `run`.                                     |
| `internal/`                    | Packages split by domain, never by layer, never `util`.                                             |
| `internal/cmd/`                | Repository tools, e.g. `repocheck`.                                                                 |
| `internal/harness/`            | Tests for the harness scripts that have failed before: the Stop hook and the commit check.          |
| `plugins/`                     | Skills packaged as plugins, each with its eval cases and `results.md`.                              |
| `conformance/`                 | The conformance suite's stack, configuration and expected results; see its README.                  |
| `tools/go.mod`, `package.json` | Pinned Go and Node tools for the gates.                                                             |
| `examples/`                    | Planned: consumers, a separate Go module that must not require pulsar; they reach it over the wire. |
| `docs/research/`               | Dated surveys with sources. Decisions cite them.                                                    |
| `docs/adr/`                    | Decisions, written through `/grill-with-docs`; created with the first one.                          |
| `docs/requirements/`           | Requirement IDs, see below; created with the first one.                                             |
| `docs/exec-plans/`             | Plans for unattended runs; format in `docs/exec-plans/PLANS.md`.                                    |
| `docs/harness.md`              | Every control in this harness, why it exists, and its evidence.                                     |
| `evals/`                       | How evals are run. Skill evals live with each plugin; evals of harness controls are planned (#3).   |
| `docs/agents/`                 | Configuration read by the engineering skills.                                                       |

## Requirements and tests

Each normative statement in scope gets an ID in `docs/requirements/`, quoting
its source clause:

```markdown
- REQ-PKCE-4 (RFC 7636 §4.6): If the values are not equal, an error response
  indicating "invalid_grant" MUST be returned.
```

A test cites the IDs it proves in a comment. `repocheck` fails the gate on an
ID no test cites, or a citation of an ID that does not exist. Never weaken or
delete a test to make it pass; if a requirement is wrong, say so and stop.

## Authorities

Where they disagree, the higher one wins. A deliberate departure is
recorded: in an ADR when it is hard to reverse, otherwise beside the thing
it changes (sandbox settings, for example, in `docs/harness.md`).

- **Behavior:** the specifications in scope, with RFC 9700 as the security
  baseline. Security work traces to a clause, not to an imagined attack.
- **Go:** the language spec, `gofmt`, `go vet` and `go fix`; then Effective
  Go; Go Code Review Comments; Go Test Comments; go.dev/doc/comment; then the
  Google Go Style Guide (Guide, then Decisions, then Best Practices).
- **Terraform:** HashiCorp's style guide and standard module structure.
- **How agents work here:** Anthropic and OpenAI guidance first, then Google,
  then AWS. Sources are in `docs/research/ai-development.md`.

## Conventions a tool does not fully check

- American English, as in the Go standard library and OAuth's own names.
  `make spell` catches common British spellings, not all of them.
- Tests are table-driven with `t.Run` where cases share a shape, and
  sequential scenarios where each step depends on the last. They compare with
  `cmp.Diff` and report `Func(args) = got, want`. Clocks use
  `testing/synctest`; key generation uses
  `testing/cryptotest.SetGlobalRandom`. Integration tests use a real
  PostgreSQL, never a mock.
- OAuth and OpenID endpoints answer errors in the form their specification
  defines (RFC 6749 §5.2), not RFC 9457.
- Dependencies: the standard library when it covers the need; otherwise the
  most widely endorsed package, with the evidence in `docs/research/`.
- Every claim in a README, doc, commit or PR is literally true. "Passes the
  OpenID conformance suite for Basic OP" is a claim; "certified" or
  "compliant" is not, until it is.
- Commits follow Conventional Commits. A `TODO` names its issue: `TODO(#12)`.

## Before a pull request

1. Review the diff against its spec with `/mattpocock-skills:code-review`.
2. Run `/security-review`.
3. After opening it, review the pull request with
   `/code-review:code-review --comment`, and resolve every thread it opens.

## Unattended runs

Before running without a human in the loop, write an ExecPlan
(`docs/exec-plans/PLANS.md`) that answers: what does done look like; how is
it checked; what may be touched; what stops it (`--max-turns`,
`--max-budget-usd`); who signs off. Its Outcomes section records turns, cost,
result and human review time.

## Deliberately not doing

| Not doing                                                                   | Until                                                                                            |
| --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Using this provider in production                                           | Never; it is a reference implementation.                                                         |
| Sign-up, password reset, MFA, social login, SAML, admin UI                  | Never; no authoritative spec, so no objective done.                                              |
| Implicit and hybrid flows, front-channel logout, session management         | Never; discouraged by RFC 9700 or fragile in current browsers.                                   |
| Dynamic Client Registration                                                 | MCP deprecated it for Client ID Metadata Documents.                                              |
| FAPI 2.0: PAR, DPoP, mTLS                                                   | Never; it needs PAR and sender-constrained tokens, a large addition beyond the Basic OP profile. |
| Token revocation (RFC 7009), introspection (RFC 7662), `client_credentials` | A consumer in `examples/` or MCP authorization support needs one; #47 defers them.               |
| Custom skills, subagents or hooks beyond `docs/harness.md`                  | A recorded failure calls for one, and an eval can measure it.                                    |
| obra/superpowers                                                            | Its always-on prompt conflicts with lean context; see `docs/research/ai-development.md`.         |
| A second vendor's model for review                                          | Calibration shows a systematic blind spot.                                                       |
| Agents running in CI                                                        | #1.                                                                                              |

## Agent skills

### Issue tracker

Issues and specs live in this repo's GitHub Issues. See
`docs/agents/issue-tracker.md`.

### Triage labels

The five canonical triage roles use their default label names. See
`docs/agents/triage-labels.md`.

### Domain docs

Single-context: `GLOSSARY.md` and `docs/adr/` at the repo root, each
created with its first entry. See `docs/agents/domain.md`.
