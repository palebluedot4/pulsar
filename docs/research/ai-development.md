# AI-assisted development: current practice

Surveyed 2026-11-04. Sources are weighted Anthropic and OpenAI first, then
Google, then AWS, with IETF/OpenID specifications governing the product itself.
Anything not confirmed against a primary source is marked **UNVERIFIED**.
Five claims were corrected on 2026-11-09, after `docs/research/evals.md`
rechecked them against their sources, and more on 2026-11-11, listed under
"Corrected 2026-11-11" below.

## The one-line consensus

The field now judges AI-assisted engineering by two questions: can you prove
the agent's output is correct, and can you prove your harness is what made it
correct? A large set of controls with no evidence that any of them helps is
read as "harness theater". Canva's interview guide lists a near relative,
"AI Showcase" (a candidate who demonstrates the tool and loses sight of the
task), among "Common approaches that don't shine".

## Consensus practices, strongest first

1. **Give the agent a runnable pass/fail check before it starts.**
   - Anthropic best practices: <https://code.claude.com/docs/en/best-practices>
   - Boris Cherny (Claude Code lead), 2026-01-02: giving Claude a way to verify
     its work "will 2-3x the quality of the final result".
     <https://threadreaderapp.com/thread/2007179832300581177>
   - Mitchell Hashimoto, "My AI Adoption Journey", 2026-02-05.
     <https://mitchellh.com/writing/my-ai-adoption-journey>
   - Nicholas Carlini, "Building a C compiler with a team of parallel Claudes",
     2026-02-05: "the task verifier [must be] nearly perfect, otherwise Claude
     will solve the wrong problem."
     <https://www.anthropic.com/engineering/building-c-compiler>
2. **A human owns intent and the final merge; changes stay small.**
   - Simon Willison, _Agentic Engineering Patterns_ (2026-02-23 onward), lists
     "inflicting unreviewed code on collaborators" as an anti-pattern.
     <https://simonwillison.net/guides/agentic-engineering-patterns/>
   - DORA 2025: AI amplifies what a team already has; "working in small
     batches" is one of the seven AI capabilities.
     <https://research.google/pubs/dora-2025-state-of-ai-assisted-software-development-report/>
   - Addy Osmani, "AI writes code faster. Your job is still to prove it
     works.", 2026-01-07: "If code touches auth, payments, secrets, or
     untrusted input", require "a human threat model review plus a security
     tool pass before merge". <https://addyosmani.com/blog/code-review-ai/>
     His "Own the Outer Loop" (2026-07-15) goes further than this item:
     agents may "choose, route, merge, and escalate safely inside a policy,
     but they cannot inherit the consequences."
     <https://addyosmani.com/blog/own-the-outer-loop/>
3. **Enforce invariants mechanically; use prose only for guidance.**
   - Anthropic separates deterministic controls (hooks, deny rules, CI) from
     non-deterministic ones (CLAUDE.md, skills): "an instruction like 'never
     edit .env' is a request, not a guarantee."
   - Birgitta Böckeler, "Harness engineering for coding agent users",
     2026-04-02: _guides_ steer before the agent acts, _sensors_ check after;
     each is _computational_ or _inferential_.
     <https://martinfowler.com/articles/harness-engineering.html>
   - OpenAI enforces architecture with custom linters and structural tests
     (see below).
4. **Keep agent context lean: a map, not an encyclopedia.**
   - Claude Code: target under 200 lines per CLAUDE.md.
     <https://code.claude.com/docs/en/memory>
   - OpenAI: AGENTS.md of ~100 lines as a table of contents.
   - Thoughtworks Radar Vol. 34 (2026-04-15): context engineering _Adopt_;
     agent instruction bloat _Caution_. <https://www.thoughtworks.com/radar>
   - Gloaguen et al., arXiv 2602.11988 (v1 2026-02-12, v3 2026-09-29):
     providing context files, LLM-generated or written by developers,
     "does not generally improve task success rates" (v3) and raises
     inference cost by over 20%.
5. **The agent that wrote the code should not judge it.**
   - Prithvi Rajasekaran, "Harness design for long-running application
     development", 2026-03-24: agents praise their own mediocre work; a
     separate, skeptical evaluator works better.
     <https://www.anthropic.com/engineering/harness-design-long-running-apps>
6. **Sandbox the agent, grant least privilege, treat prompt injection as a
   design constraint.**
   - Anthropic, "Beyond permission prompts", 2025-10-20: sandboxing cut
     permission prompts by 84%.
     <https://www.anthropic.com/engineering/claude-code-sandboxing>
   - Aikido "PromptPwnd" (2025-12-04): prompt injection through issue and
     pull request text into AI agents in CI. Gemini CLI's action leaked
     secrets; for Claude Code's action, Aikido calls leaking a privileged
     `GITHUB_TOKEN` "_almost_ always possible" only where untrusted users can
     trigger it (`allowed_non_write_users: "*"`), which the default forbids.
     <https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents>
7. **Structure long runs.** Initializer session; a feature list that starts
   all-failing where the agent may change only the `passes` field; one feature
   per session; a progress file; a clean commit at the end. Editing or removing
   tests is "unacceptable".
   <https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents>
   (2025-11-26)
8. **Evaluate the harness itself against a baseline, and read transcripts.**
   - "Demystifying evals for AI agents", 2026-01-09: start with 20–50 tasks
     drawn from real failures; grade outcomes, not paths; report pass@k vs
     pass^k; calibrate LLM judges against humans.
     <https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents>
   - Rajasekaran: "every component in a harness encodes an assumption about
     what the model can't do" — remove pieces one at a time and see what breaks.
   - Infrastructure noise alone moved Terminal-Bench scores by 6 points
     (2026-02-05). <https://www.anthropic.com/engineering/infrastructure-noise>
     Pin models and repeat runs.
9. **Feedback flywheel.** Every repeated agent mistake becomes a harness
   change, and rules that no longer earn their place are removed
   (Hashimoto; Böckeler; Radar "Feedback flywheel", _Assess_ in April 2026,
   _Trial_ in Vol. 35: "The flywheel needs to remove as well as add.").
   <https://www.thoughtworks.com/radar/techniques/feedback-flywheel>
10. **Check the quality of AI-written tests.** Böckeler rates behavior
    harnesses the weakest category; Radar puts mutation testing in _Adopt_
    (Vol. 35; _Trial_ in April 2026); Kent Beck (2025-06-25) names as a
    warning sign "the genie was cheating, for example by disabling or
    deleting tests"
    (<https://newsletter.kentbeck.com/p/augmented-coding-beyond-the-vibes>);
    agentic property-based testing found real NumPy bugs (arXiv 2510.09907).
11. **Parallelize only truly independent work, each agent in its own
    checkout.** Radar put "coding agent swarms" in _Caution_ in April 2026;
    Vol. 35 does not repeat the blip.
12. **Agents in CI and on schedules, with budgets** (claude-code-action,
    OpenAI's recurring cleanup agents).
13. **Track cost and telemetry** — supporting evidence, not a headline.

## Anthropic specifics

### How to grow a harness

- "You don't need to configure everything up front." Start with CLAUDE.md and
  add extensions as triggers appear.
  <https://code.claude.com/docs/en/features-overview>

  | Trigger                                   | Add              |
  | ----------------------------------------- | ---------------- |
  | Claude gets the same thing wrong twice    | a CLAUDE.md line |
  | The same prompt is typed repeatedly       | a skill          |
  | Side-task output floods the session       | a subagent       |
  | It must happen every time, without asking | a hook           |
  | A second repository needs it              | a plugin         |

- The best-practices page has a section titled "What you can stop doing";
  harness subtraction is part of the practice.
- Steering blog (Michael Segner, 2026-06-18): "Keep CLAUDE.md under 200 lines,
  give it an owner, and review changes to it like code."
  <https://claude.com/blog/steering-claude-code-skills-hooks-rules-subagents-and-more>
- When a repo already uses AGENTS.md, Claude Code reads it via a CLAUDE.md that
  imports it. AGENTS.md was donated to the Linux Foundation's Agentic AI
  Foundation on 2025-12-09 alongside MCP; AWS, Google, Microsoft, Anthropic and
  OpenAI are platinum members.
  <https://www.linuxfoundation.org/press/linux-foundation-announces-the-formation-of-the-agentic-ai-foundation>

### Planning and specs

- "Interview me until you could write the spec, then write it to SPEC.md",
  then build in a fresh session; review the diff against SPEC.md with a
  subagent, "skip style". (best practices)
- Teams report, 2025-07-24: "Starting over often has a higher success rate
  than trying to fix Claude's mistakes"; Security Engineering drives Claude
  through test-driven development.
  <https://claude.com/blog/how-anthropic-teams-use-claude-code>
- "If you've corrected the same thing twice … `/clear` plus one new prompt."

### Code review

Three distinct products, easily confused:

| Name                                  | What it is                                                                                                                                                        | Version follows                                         |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| `/code-review`                        | Skill bundled in the Claude Code binary; runs as a forked subagent with its own context; effort `low`…`max`, plus `ultra`; `--fix`, `--comment`, `--max-findings` | Claude Code version                                     |
| `code-review@claude-plugins-official` | Open-source multi-agent PR review plugin                                                                                                                          | The plugin manifest's `version`, 1.0.1 since 2026-10-26 |
| Code Review (a managed service)       | GitHub app for Team/Enterprise plans, ~$15–25 and ~20 min per review                                                                                              | Anthropic-hosted                                        |

**The plugin's current command** (`plugins/code-review/commands/code-review.md`,
revised 2026-01 to 2026-03, synced into the official marketplace 2026-10-26):

1. A Haiku agent checks eligibility (skip closed, draft, trivial PRs).
2. A Haiku agent collects relevant CLAUDE.md files; a Sonnet agent summarizes
   the PR.
3. Four reviewers in parallel: two Sonnet agents for CLAUDE.md compliance
   (deliberately redundant); one Opus bug agent restricted to the diff — "Do
   not flag issues that you cannot validate without looking at context
   outside of the git diff"; one Opus agent for security and logic errors.
4. Each candidate issue is validated by its own subagent; unvalidated issues
   are dropped.
5. An explicit exclusion list: pre-existing issues, anything a linter catches,
   general quality concerns not required by CLAUDE.md.

Principle: "We only want HIGH SIGNAL issues … False positives erode trust."
The plugin's README describes an earlier design: four parallel agents, each
issue scored 0–100 and those below 80 dropped, with no model named
(corrected 2026-11-09, `docs/research/code-review-tools.md`).

**Code Review**, "a managed service" (launched 2026-03-09): find → verify
(separate verifier agents filter false positives) → rank by severity
(Important, Nit, Pre-existing) → post. It reads `REVIEW.md` from the base
branch. Reported internal results: substantive review comments rose from 16%
to 54% of PRs; fewer than 1% of findings marked incorrect.
<https://claude.com/blog/code-review>, <https://code.claude.com/docs/en/code-review>

**How Anthropic secures its own SDLC** (Jason Clinton, 2026-07-21): Claude
authors about 80% of merged code; agents run `/security-review` before opening
a PR; CI runs multiple narrowly focused review agents plus SAST; human review
is risk-tiered; agents run on egress-allowlisted VMs with single-purpose
identities.
<https://claude.com/blog/how-anthropic-secures-its-ai-native-software-development-lifecycle>

### Bounding autonomous loops

- Pre-flight checklist before leaving a task unattended: what does done look
  like; can it check its own work; what may it touch; **what stops it**; who
  signs off. Its fan-out example uses
  `claude --bare -p … --permission-mode dontAsk --max-turns 20` and "try it on
  three files first".
- `--max-turns` and `--max-budget-usd` apply in print mode; spend can overshoot
  the cap by the response that crosses it. The Agent SDK example uses
  `max_turns=30`. <https://code.claude.com/docs/en/agent-sdk/agent-loop>
- Stop hooks: Claude Code overrides a Stop hook after it blocks **eight**
  times in a row with no tool call in between (`CLAUDE_CODE_STOP_HOOK_BLOCK_CAP`);
  scripts should exit early when `stop_hook_active` is true.
  <https://code.claude.com/docs/en/hooks-guide>
- `/goal` wraps a prompt-based Stop hook judged by a small model that does not
  run commands, so it cannot replace a real gate. It has no built-in turn cap;
  write the bound into the condition ("or stop after 20 turns").
  <https://code.claude.com/docs/en/goal>
- Auto mode falls back to prompting after 3 consecutive or 20 total blocks.
- No documented "fail N times, then escalate to a human" constant (UNVERIFIED
  absence).

### Skills and subagents

- Skills: `description` in third person, up to 1,024 characters; body under
  500 lines; references one level deep. **"Create evaluations BEFORE writing
  extensive documentation"**: identify gaps, build three scenarios, measure a
  baseline, then write minimal instructions.
  <https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices>
- Subagents: for verbose side tasks, tool restriction, or self-contained work
  that returns a summary. A fresh context sees no conversation history; remove
  the `Agent` tool to keep a reviewer read-only.
  <https://code.claude.com/docs/en/sub-agents>

### Plugins: declaration and updates

- Declare at project scope in the committed `.claude/settings.json` with
  `extraKnownMarketplaces` and `enabledPlugins` (`"name@marketplace": true`).
  Applies after the workspace trust dialog; `-p`/CI runs need the official
  marketplace declared explicitly.
  <https://code.claude.com/docs/en/plugins/org.md>
- Official-marketplace plugins auto-update by default (within ~10 minutes of
  a session's first message); others do not. `enabledPlugins` cannot pin a
  version; a marketplace entry can pin `sha`. `code-review` sets
  `"version": "1.0.1"` in its manifest since 2026-10-26; `mattpocock-skills`
  is pinned by SHA in the catalog.
- `DISABLE_AUTOUPDATER`, `DISABLE_UPDATES` and
  `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` each turn off the background
  update pass, unless `FORCE_AUTOUPDATE_PLUGINS=1` is set. A second path is
  separate: `claude plugin install name@marketplace` refreshes that
  marketplace first, and that refresh "doesn't depend on the marketplace's
  auto-update setting or on `DISABLE_AUTOUPDATER`". Of the three variables,
  only `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` is among the cases that
  skip it, with a refresh in the last 30 seconds and some kinds of
  marketplace source. The page does not name `DISABLE_UPDATES` there; that
  it does not stop the refresh is observed only
  (`docs/research/code-review-tools.md`).
  <https://code.claude.com/docs/en/plugins/loading.md>
- Consequence for evals: record the Claude Code version, model IDs and plugin
  SHAs with every result, and freeze updates while running a comparison.

### CI and observability

- `anthropics/claude-code-action@v1` takes `plugins` and `plugin_marketplaces`
  inputs; the documented review workflow installs
  `code-review@claude-plugins-official`.
  <https://code.claude.com/docs/en/github-actions>
- Hardening (`docs/security.md`, 2026-08-05): write access required to
  trigger; never check out an untrusted ref at the workspace root under
  `pull_request_target`; `.claude/` and `CLAUDE.md` are restored from the base
  branch; prefer OIDC workload identity over stored keys.
  <https://github.com/anthropics/claude-code-action/blob/main/docs/security.md>
- Auth: `claude_code_oauth_token` (from `claude setup-token`) is supported, but
  the docs recommend an API key for CI because the OAuth token is tied to one
  person's subscription; subscription use is meant for "ordinary, individual
  usage". <https://code.claude.com/docs/en/legal-and-compliance.md>
- Telemetry: `CLAUDE_CODE_ENABLE_TELEMETRY=1`; metrics include
  `claude_code.cost.usage`, `token.usage`, `pull_request.count`; events
  include `api_request` with `cost_usd`.
  <https://code.claude.com/docs/en/monitoring-usage>

## OpenAI specifics

**"Harness engineering: leveraging Codex in an agent-first world"** (Ryan
Lopopolo, 2026-02-11; read via a Wayback Machine snapshot because openai.com
returns 403). <https://openai.com/index/harness-engineering/>

- About 1M lines and ~1,500 merged PRs from an empty repo; "Humans steer.
  Agents execute."
- A single large AGENTS.md failed (crowds out context, goes stale, cannot be
  checked mechanically). Theirs is ~100 lines and points into `docs/`, the
  system of record: `design-docs/`, `exec-plans/{active,completed}/`,
  `product-specs/`, `references/`, plus quality and reliability documents.
  Docs are linted and kept fresh by a recurring "doc-gardening" agent.
- Architecture is enforced by custom linters and structural tests whose error
  messages are written as remediation instructions for the agent.
- Recurring "garbage-collection" agents replaced a weekly manual cleanup of
  "AI slop", opening small refactor PRs.
- Each worktree boots its own app and observability stack so agents can verify
  runtime behavior.
- Divergence from Anthropic: human review is optional, loops run "until all
  agent reviewers are satisfied" with no hard cap, and the only reported
  metrics are throughput. The post says the approach "should not be assumed to
  generalize".

**Codex documentation** (read 2026-11-04):

- AGENTS.md: one file per directory, nearest wins; 32 KiB default cap.
  <https://learn.chatgpt.com/docs/agent-configuration/agents-md>
- When to add a rule, from the best-practices guide rather than the AGENTS.md
  page: "When Codex makes the same mistake twice, ask it for a retrospective
  and update `AGENTS.md`." <https://learn.chatgpt.com/guides/best-practices>
- Code review flags only P0/P1 issues; review rules live in AGENTS.md.
  <https://learn.chatgpt.com/docs/third-party/github.md>
- "A Practical Approach to Verifying Code at Scale" (2025-12-01): accepted
  "modestly reduced recall in exchange for high signal quality"; the reviewer
  is "a support tool, not a replacement for careful judgment".
  <https://alignment.openai.com/scaling-code-verification/>
- ExecPlans: a `PLANS.md` format with living sections — Progress, Surprises &
  Discoveries, Decision Log, Outcomes & Retrospective — self-contained and
  ending in demonstrably working behavior.
  <https://developers.openai.com/cookbook/articles/codex_exec_plans>
- Best practices: "only schedule work that already runs reliably by hand".
  <https://learn.chatgpt.com/guides/best-practices>

## Google and AWS, briefly

- **DORA 2025 AI Capabilities Model** (2025-09-24): clear and communicated AI
  stance; healthy data ecosystems; AI-accessible internal data; strong version
  control practices; working in small batches; user-centric focus; quality
  internal platforms.
  <https://cloud.google.com/blog/products/ai-machine-learning/introducing-doras-inaugural-ai-capabilities-model>
- **Google Conductor** (2025-12-17): Context → Spec & Plan → Implement, with
  human approval of the plan; automated reviews added 2026-02-13.
  <https://developers.googleblog.com/conductor-introducing-context-driven-development-for-gemini-cli/>
- **AWS AI-DLC** (2025-07-31) and Kiro: the heaviest upfront-spec approach
  (EARS requirements, approval gates, team "mob" rituals).
  <https://aws.amazon.com/blogs/devops/ai-driven-development-life-cycle/>,
  <https://kiro.dev/docs/specs/>
- Being retired or superseded, so not to be featured: Amazon Q Developer
  (end of support 2027-04-30, succeeded by Kiro); Jules (read-only from
  2026-11-11); Gemini CLI (folded into Antigravity CLI); the awslabs Terraform
  MCP server (superseded by HashiCorp's).
- Real-need MCP servers for an AWS deployment: the AWS MCP Server (GA
  2026-05-06) and HashiCorp's terraform-mcp-server.

**Cross-vendor agreement:** repo-resident context files, plan before code with
human approval, small units of work, deterministic verification over
instructions, independent review against the spec, and audit trails.
**Disagreement:** how much spec up front (AWS heaviest, Anthropic/OpenAI
lightest) and team rituals versus a single developer orchestrating agents.

## Contested or overhyped

- Heavy spec-driven development: Böckeler warns "spec-as-source" combines
  model-driven rigidity with LLM non-determinism (2025-10-15); Spec Kit and
  OpenSpec are only _Assess_ on the Radar.
- Ralph loops (_Assess_; its author recommends greenfield only) and coding
  agent swarms (_Caution_, April 2026). "Dark factory" autonomy is not a
  Radar blip; no Vol. 35 technique carries the name.
- Throughput as a productivity measure (_Caution_). METR (2026-02-24) calls
  the data from its new experiment, started in August 2025, "an unreliable
  signal" of AI tools' current productivity effect, because of selection
  effects.
  <https://metr.org/blog/2026-02-24-uplift-update/>
- LLM-as-judge without calibration; MCP by default (_Caution_).

## Workflow skill libraries

Data pulled 2026-11-04:

| Measure                      | mattpocock/skills            | obra/superpowers             |
| ---------------------------- | ---------------------------- | ---------------------------- |
| GitHub stars                 | ~311.9k                      | ~312.0k                      |
| In `claude-plugins-official` | Yes (2026-07-27), pinned SHA | Yes (2026-01-15)             |
| claude.com/plugins installs  | 1,745                        | ~1.01M, "Anthropic verified" |
| skills.sh leaderboard        | 11 of the top 20             | best entry #193              |

Superpowers is the more installed library inside Claude Code. Its
`using-superpowers` skill is injected by a SessionStart hook into every
session and instructs: "If you think there is even a 1% chance a skill might
apply … you ABSOLUTELY MUST invoke the skill", which conflicts with the
lean-context guidance above. Matt Pocock's library consists of small,
composable skills whose artifacts are GitHub issues, ADRs and a glossary.
Accurate description: "widely adopted and listed in Anthropic's official
marketplace", not "the most endorsed".

## Hiring signals

- Canva AI interview guide (2025-10-20): scores problem-solving, technical
  depth and ownership, and AI collaboration; under "Common approaches that
  don't shine" it lists "AI Showcase", "Feature Marathon" and "Hands-Off".
  The guide does not use the words "red flag".
  <https://www.canva.dev/blog/engineering/ai-interview-success/>
- Karat rubric (2026): "AI Proficiency" means recognizing wrong AI output,
  testing it and adapting it.
  <https://karat.com/resource/human-ai-technical-interview-rubrics/>
- Shopify memo (2025-04-07): "Reflexive AI usage is now a baseline
  expectation."
- No primary source describes what interviewers look for in AI-assisted
  portfolio repositories (UNVERIFIED absence). The rubrics above consistently
  reward verification, ownership and judgment over tool display.

## Added 2026-11-05

Found by an audit of this repository's harness in a separate Claude session
that had not written it (the same model, so its blind spots overlap with the
author's), then checked against primary sources.

- **Thoughtworks Radar Vol. 35** (2026-11-04): agent sandboxing, mutation
  testing and progressive context disclosure in _Adopt_; feedback flywheel and
  self-improving harness in _Trial_; harness quality evaluation and zizmor in
  _Assess_; agent instruction bloat and human-in-the-loop theater in
  _Caution_. On harness evaluation: "We recommend running evaluations on a
  scheduled basis (such as nightly or alongside CI)."
  <https://www.thoughtworks.com/radar>
- **Naresh Jain, "Are Harnesses Worth the Cost?"** (2026-10-13): ten paired
  runs per model on one Java service, with and without a harness, scored by
  178 hidden acceptance tests, using OpenAI's GPT-6 Sol and Luna. The
  frontier model passed every evaluation either way; there the harness used
  about 10.5× the tokens and 7× the cost and "added overhead without a
  detected acceptance benefit". The cheaper model went from 3 of 10 to 10 of
  10 with it. One service and two non-Claude models do not transfer to
  Claude; what does transfer is that harness evals need the model and the
  cost as dimensions, not only pass rates.
  <https://martinfowler.com/articles/are-harnesses-worth-the-cost.html>
- **Birgitta Böckeler, "TDD inside the agent loop - theater or actual
  value?"** (2026-08-10): "no clearly discernable difference based on TDD
  workflow versus no TDD workflow", at 2.96–8.50× the tokens (her heading
  says "At least 3x"; the page prints no date, the series index gives
  2026-08-10). She recommends outcome-based checks instead: mutation
  testing, automated outcome feedback, static analysis, structure reviews.
  <https://martinfowler.com/articles/exploring-gen-ai/tdd-in-the-agent-loop.html>
- **Anthropic, "How we contain Claude across products"** (2026-05-25): "if
  credentials never enter the sandbox, they can't be exfiltrated."
  <https://www.anthropic.com/engineering/how-we-contain-claude>
- **Anthropic, "Redesigning source control at Anthropic"** (2026-10-13):
  "Our team members still review every change request for the system, but
  they now examine the intent of the change."
  <https://www.anthropic.com/engineering/redesigning-source-control>
- **`claude plugin eval`**: runs each case three times by default, reports
  with, without and the difference (`--ablation with-without`), and has a
  `--json` mode. It loads only the plugin under test — "no `.claude/`
  directory, `CLAUDE.md`, or `.mcp.json` loads" — so it can evaluate skills
  but not repository hooks or gates. Models are pinnable, not pinned by
  default. <https://code.claude.com/docs/en/plugin-evals>
- **Claude Code reads `AGENTS.md` natively** from v2.1.277; a `CLAUDE.md`
  containing `@AGENTS.md` can stay, and never causes a double read.
  <https://code.claude.com/docs/en/memory>
- **Sandbox settings**: `allowUnsandboxedCommands` defaults to `true`;
  Anthropic's hardened example sets it to `false`. `enableWeakerNetworkIsolation`
  lets Go tools reach macOS's TLS trust service when traffic passes through a
  MITM proxy with a custom CA, and "reduces security by opening a potential
  data exfiltration path". A marketplace's `autoUpdate` decides for that
  marketplace whether the background pass updates it, and
  `DISABLE_AUTOUPDATER=1` switches that pass off, not the refresh before an
  install (see "Plugins: declaration and updates" above).
  <https://code.claude.com/docs/en/settings-reference>
- **GitHub Copilot cloud agent** opens pull requests under its own app
  identity, pushes only to `copilot/` branches, and "prevents the user who
  asked Copilot cloud agent to create a pull request from approving it" — the
  reference model for separating an agent's identity from its reviewer's.
  <https://docs.github.com/en/copilot/concepts/agents/cloud-agent/risks-and-mitigations>
- **OWASP Top 10 for Agentic Applications 2026** (2025-12-09) includes
  Identity and Privilege Abuse (ASI03) and Agentic Supply Chain
  Vulnerabilities (ASI04); names from secondary sources, as the PDF was not
  reached (UNVERIFIED).
- **zizmor**, static analysis for GitHub Actions security
  (`dangerous-triggers`, `excessive-permissions`, `unpinned-uses`,
  `template-injection`); its documented catches include
  `anthropics/claude-code-action#729`. <https://docs.zizmor.sh/>
- **Provenance trailers**: LLVM asks for `Assisted-by:`; the ASF for
  `Generated-by:` or `Co-authored-by:`. The Linux kernel decided at its
  2026-10-08 Maintainers Summit to remove its `Assisted-by:` requirement.
  <https://lwn.net/Articles/1099594/>

## Corrected 2026-11-11

Rechecked against the sources by a session that had not written them, in
the same model; every source below was read again on 2026-11-11.

- **Osmani.** The auth and security point was cited to "Own the Outer
  Loop", which mentions neither; it is from "AI writes code faster. Your
  job is still to prove it works." (2026-01-07).
- **Canva.** The guide never says "red flag"; the three approaches sit under
  "Common approaches that don't shine".
- **Radar rings.** Feedback flywheel and mutation testing were given their
  April 2026 rings, _Assess_ and _Trial_, though Vol. 35 (2026-11-04), cited
  further down this file, has them in _Trial_ and _Adopt_.
- **Kent Beck.** Agents deleting tests to make them "pass" is Gergely
  Orosz's summary (Pragmatic Engineer, 2025-06-11), not Beck's words; his
  own are now quoted.
- **"Dark factory".** It was listed as a Radar _Caution_ blip; the Radar has
  no blip by that name.
- **Update variables, twice.** "`DISABLE_AUTOUPDATER` / `DISABLE_UPDATES`
  freeze updates" and "`DISABLE_AUTOUPDATER=1` still switches every update
  off": the plugin loading page documents that the refresh before an
  install depends on neither `autoUpdate` nor `DISABLE_AUTOUPDATER`, as
  #92 observed.
- **PromptPwnd.** The condition under which Claude Code's action is
  exposed was missing.

## Still unverified

- Exact agent counts per effort level of the bundled `/code-review`.
- Details of Meta's AI-enabled interview rubric.
- Whether `claude-code-action` accepts a pinned ref in `plugin_marketplaces`.
