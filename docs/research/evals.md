# Evals: which harness controls to measure, and how

Surveyed 2026-11-09 for #3, #4 and #5 and for the Evidence column of
`docs/harness.md`, which then marked most controls "Hypothesis" and the
three review controls "Pending ablation". It answers three questions.
Which kinds of harness component do Anthropic, OpenAI, Google, AWS and
credible practitioners evaluate with evals, and which do they justify by
other evidence? How do organizations measure whether an AI code reviewer, or
several stacked review passes, helps? When do sources judge evals not worth
their cost, and what do they recommend instead? Sources are the owners'
own posts, documentation, papers and code, all read on 2026-11-09; a
publication date is given where the source prints one. Anything not
confirmed against a primary source is marked **UNVERIFIED**, and an absence
that could not be confirmed is marked "(UNVERIFIED absence)".

## What gets evaluated, and what is justified otherwise

### The team's own skills, prompts and agents

| Source                                                                                                                         | What it evaluates                                                                         | How                                                                                                                    | Quote                                                                                                                           |
| ------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Anthropic, Skill authoring best practices                                                                                      | Skills the reader writes                                                                  | Run Claude without the skill, build three scenarios from the gaps, measure a baseline, then write minimal instructions | "Create evaluations BEFORE writing extensive documentation."                                                                    |
| Anthropic, `claude plugin eval` documentation                                                                                  | Plugins and skills, with and without                                                      | Each case three times by default, a no-plugin baseline arm, deterministic or judge graders                             | "This page is for plugin and skill authors who have a working plugin and want to test its behavior"                             |
| OpenAI, "Testing Agent Skills Systematically with Evals" (no date or author printed)                                           | Skills the reader iterates on                                                             | `codex exec --json` traces checked deterministically, plus rubric grading                                              | "For a single skill, a small set of 10–20 prompts is enough to surface regressions and confirm improvements early."             |
| Anthropic, "Demystifying evals for AI agents" (2026-01-09)                                                                     | The agent: harness and model together                                                     | 20–50 tasks from real failures; grade the outcome; read transcripts                                                    | "we're evaluating the harness _and_ the model working together"                                                                 |
| Google Cloud, "A methodical approach to agent evaluation" (Hugo Selbie, 2025-11-18)                                            | Final outcome, trajectory and tool use, trust and safety                                  | A suite that runs on every change and fails the build below a threshold; LLM judges aligned to human labels            | "Your evaluation suite should act as a **quality gate** that runs automatically with every proposed change to the agent."       |
| Google Cloud, "Four eval engineering lessons" (Casey West, 2026-10-17)                                                         | The composite stack: harness, model, tools and plugins                                    | Golden sets; score the tool-call trajectory, not the final reply                                                       | "Build golden sets based on what the entire system should actually do in the wild, including your harness, model, and plugins." |
| AWS, "Evaluating AI agents: Real-world lessons from building agentic systems at Amazon" (Bai, Colin, Imran, Xiong, 2026-02-18) | Three layers: the model, agent components such as tool use and memory, the final response | An evaluation library over agent traces, human audits, production monitoring with alerts                               | Traditional methods "treat agent systems as black boxes and evaluate only the final outcome"                                    |

Sources:
<https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices>,
<https://code.claude.com/docs/en/plugin-evals>,
<https://developers.openai.com/blog/eval-skills>,
<https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents>,
<https://cloud.google.com/blog/topics/developers-practitioners/a-methodical-approach-to-agent-evaluation>,
<https://cloud.google.com/blog/topics/developers-practitioners/four-eval-engineering-lessons>,
<https://aws.amazon.com/blogs/machine-learning/evaluating-ai-agents-real-world-lessons-from-building-agentic-systems-at-amazon/>.

All seven address whoever builds the agent or the skill. Google's golden
sets take in plugins as part of the whole system; none of the seven
evaluates one plugin or skill that someone else wrote on its own (see
below).

### Context files

| Source                                                                                   | Evidence used                       | Quote                                                                                                                                                                                                        |
| ---------------------------------------------------------------------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Anthropic, Claude Code best practices, "Keep CLAUDE.md short"                            | Repeated corrections                | What belongs in the file includes "Anything you've had to correct twice already"                                                                                                                             |
| OpenAI, Codex best practices                                                             | Repeated mistakes                   | "When Codex makes the same mistake twice, ask it for a retrospective and update `AGENTS.md`."                                                                                                                |
| Gloaguen et al., "Evaluating AGENTS.md", arXiv 2602.11988 (v1 2026-02-12, v3 2026-09-29) | A controlled eval, with and without | v3: providing context files "does not generally improve task success rates", and raises inference cost "by over 20%"; "any attempts to improve performance should be rigorously evaluated before deployment" |
| Thoughtworks Radar Vol. 35 (2026-11-04), harness quality evaluation, _Assess_            | Evals of harness parts              | Names AGENTS.md files among the parts of custom harnesses; see the next table                                                                                                                                |

Sources: <https://code.claude.com/docs/en/best-practices>,
<https://learn.chatgpt.com/guides/best-practices>,
<https://arxiv.org/abs/2602.11988>,
<https://www.thoughtworks.com/radar/techniques/harness-quality-evaluation>.

Vendors justify a line in a context file by a mistake that recurred. The
only controlled study found evaluates context files as a whole, not line by
line, and found no general benefit.

### Hooks and deterministic gates

| Source                                                                       | Evidence used                                   | Quote or finding                                                                                                                                                                                                                                                                     |
| ---------------------------------------------------------------------------- | ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Thoughtworks Radar Vol. 35, harness quality evaluation                       | Plugins and skills by eval; guardrails by tests | For non-deterministic parts such as plugins or skills, its teams use PluginEval; for deterministic guardrails, a test suite that gives evidence each guardrail is effective (paraphrase). "We recommend running evaluations on a scheduled basis (such as nightly or alongside CI)." |
| Birgitta Böckeler, "Harness engineering for coding agent users" (2026-04-02) | An open problem                                 | "We need a way to evaluate harness coverage and quality similar to what code coverage and mutation testing do for tests." "If sensors never fire, is that a sign of high quality or inadequate detection mechanisms?"                                                                |
| Anthropic, Claude Code best practices                                        | Determinism itself                              | Its table puts "Tests, typecheck, a `Stop` hook, CI" in its "Deterministic (Claude Code enforces)" column for "When it's done"; a rule that cannot bend becomes "a hook or a deny rule"                                                                                              |
| Anthropic, "Demystifying evals for AI agents"                                | Deterministic graders                           | "Deterministic graders are natural for coding agents because software is generally straightforward to evaluate."                                                                                                                                                                     |

Sources: <https://www.thoughtworks.com/radar/techniques/harness-quality-evaluation>,
<https://martinfowler.com/articles/harness-engineering.html>,
<https://code.claude.com/docs/en/best-practices>.

No source found evaluates a linter, formatter or commit check by running an
agent with and without it (UNVERIFIED absence). Thoughtworks' evidence for
a deterministic guardrail is its own test suite; Böckeler's open question is
whether a sensor that never fires is working.

### Third-party skills and plugins

| Source                                          | Evidence used                   | Quote                                                                                                                                                                                                                                                                                          |
| ----------------------------------------------- | ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Anthropic, Agent Skills overview                | Trust in the source, and audit  | "Use Skills only from trusted sources: those you created yourself or obtained from Anthropic." Otherwise "Audit thoroughly", reviewing "all files bundled in the Skill"                                                                                                                        |
| Anthropic, Plugin security and trust            | Trust in the source, and review | "A marketplace's name tells you who publishes the catalog, not what each plugin in it does"; the install warning: "Anthropic does not control what MCP servers, files, or other software are included in plugins and cannot verify that they will work as intended or that they won't change." |
| Anthropic, `claude plugin eval` documentation   | Possible, not recommended       | A target can be "An installed plugin by name", so a user could evaluate a plugin they did not write; "only evaluate plugins you trust"                                                                                                                                                         |
| Anthropic, `claude-code-security-review` source | The vendor's own eval tool      | Its `claudecode/evals` runs the reviewer "on any GitHub PR to analyze its security findings", for "Evaluating performance and accuracy" (at commit `0c6a49f`, 2026-02-11)                                                                                                                      |

Sources: <https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview>,
<https://code.claude.com/docs/en/plugins/security>,
<https://code.claude.com/docs/en/plugin-evals>,
<https://github.com/anthropics/claude-code-security-review/tree/main/claudecode/evals>.

Anthropic's guidance for a skill or plugin someone else wrote is a trust
decision and an audit of what it runs, not an eval. No source found tells a
user to re-evaluate a third-party skill's effectiveness (UNVERIFIED
absence). Whether the bundled `/security-review` uses the same prompt as the
open-source action is **UNVERIFIED**.

### The harness as a whole

- **Rajasekaran, "Harness design for long-running application development"
  (Anthropic, 2026-03-24):** "every component in a harness encodes an
  assumption about what the model can't do on its own". After a radical
  simplification lost performance, he removed one component at a time and
  reviewed its effect, and judged the evaluator agent by reading its logs
  against his own judgment. No run with versus without the evaluator alone
  is reported.
  <https://www.anthropic.com/engineering/harness-design-long-running-apps>
- **Naresh Jain, "Are Harnesses Worth the Cost?" (2026-10-13):** ten runs
  per model with and without a behavioral harness, scored by 178 acceptance
  tests the harness never saw. Guides and sensors were added together, so,
  as his caveats say, the contribution of each could not be isolated.
  <https://martinfowler.com/articles/are-harnesses-worth-the-cost.html>
- **Böckeler, "TDD inside the agent loop - theater or actual value?"
  (2026-08-10, the date in the series index):** five batches, two runs per
  arm each, compared by design and test quality and mutation score.
  <https://martinfowler.com/articles/exploring-gen-ai/tdd-in-the-agent-loop.html>

## How review agents are measured

### Production signals

| Organization | Metric                                                                         | How measured                                                                                                                                                               | Result                                                                                                                                                                                                                                               | Source                                                                                          |
| ------------ | ------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Anthropic    | Share of PRs with substantive comments; findings marked incorrect              | Internal use; the method is not described                                                                                                                                  | "Before, 16% of PRs got substantive review comments. Now 54% do."; "less than 1% of findings are marked incorrect"; 84% of PRs over 1,000 lines get findings, averaging 7.5; 31% under 50 lines, averaging 0.5; $15–25 and about 20 minutes a review | "Code Review" launch post, 2026-03-09                                                           |
| Anthropic    | Comments resolved because addressed; findings by severity; cost per repository | The Code Review analytics page                                                                                                                                             | "Count of review comments that were auto-resolved because a developer addressed the issue"                                                                                                                                                           | Code Review costs and usage documentation                                                       |
| Anthropic    | Incidents that review would have caught                                        | Retrospective over past claude.ai incidents; new reviewers start in shadow mode, are red-teamed, and a risk-weighted sample of automated approvals is checked by people    | About a third of the bugs behind past incidents would have been caught by the current automated processes (paraphrase); no false-positive or acted-on rate                                                                                           | Jason Clinton, "How Anthropic secures its AI-native software development lifecycle", 2026-07-21 |
| Anthropic    | Catches                                                                        | Two anecdotes                                                                                                                                                              | The GitHub action found a remote code execution "exploitable through DNS rebinding" and a proxy "vulnerable to SSRF attacks"; no rates                                                                                                               | "Automate security reviews with Claude Code", 2025-08-06                                        |
| OpenAI       | Comments addressed with a code change; reactions                               | Production                                                                                                                                                                 | "authors address it with a code change in 52.7% of cases"; comments on 36% of Codex-generated PRs, 46% of which lead to a change; "over 80% of comment reactions being positive"; "more than 100k external PRs per day"                              | "A Practical Approach to Verifying Code at Scale", 2025-12-01                                   |
| GitHub       | Reviews with actionable feedback; positive feedback; latency                   | Internal testing against known issues, thumbs reactions, whether flagged issues are resolved before merge                                                                  | "In 71% of the reviews, Copilot code review surfaces actionable feedback."; "In the remaining 29%, the agent says nothing at all."; about 5.1 comments a review; a reasoning model raised positive feedback 6% and latency 16%                       | "60 million Copilot code reviews and counting", 2026-03-05                                      |
| GitHub       | Addressed rate                                                                 | `total_comments_addressed` over `total_comments_evaluated`; acted on counts an applied suggestion, a fix asked of Copilot, an edit, or a reply that a later PR will handle | Also `total_merged_no_human_change_request_after_review`                                                                                                                                                                                             | Changelog, 2026-11-05                                                                           |
| Google       | Useful ratio, resolution, A/B                                                  | Thumbs on about 10% of comments; 15 raters on about 370 comments; a randomized experiment over about half of developers                                                    | Useful ratio 54% rising to 66% after suppressing non-actionable rules; estimated resolution about 40%; no significant change in review duration; "Intrinsic evaluations and real-world performance can diverge significantly."                       | AutoCommenter, arXiv 2405.13565 (May 2024)                                                      |
| Google       | Edits applied to reviewer comments                                             | Offline at a 50% target precision, then online                                                                                                                             | Offline the model "addresses 52% of comments with a target precision of 50%"; "40% to 50% of all previewed suggested edits are applied"; later, ">8%" of review comments "are now addressed with AI-based assistance"                                | Research blog, 2023-05-23 and 2024-06-06                                                        |
| Meta         | Fixes applied; review time                                                     | A safety trial before rollout, then production                                                                                                                             | With AI patches shown to reviewers, they took "over 5% longer"; shown to authors only, no regression; ActionableToApplied 19.7%                                                                                                                      | MetaMateCR, arXiv 2507.13499, 2025-07-17                                                        |
| Meta         | Reverts and incidents of automatically approved low-risk diffs                 | Telemetry over more than 535K diffs; difference-in-differences                                                                                                             | Revert rate about a third, incident rate about a fiftieth, of other diffs                                                                                                                                                                            | RADAR, arXiv 2605.30208, 2026-05-28                                                             |

Sources: <https://claude.com/blog/code-review>,
<https://code.claude.com/docs/en/code-review-costs>,
<https://claude.com/blog/how-anthropic-secures-its-ai-native-software-development-lifecycle>,
<https://claude.com/blog/automate-security-reviews-with-claude-code>,
<https://alignment.openai.com/scaling-code-verification/>,
<https://github.blog/ai-and-ml/github-copilot/60-million-copilot-code-reviews-and-counting/>,
<https://github.blog/changelog/2026-11-05-usage-metrics-api-adds-code-review-details-and-addressed-rate>,
<https://arxiv.org/html/2405.13565v1>,
<https://research.google/blog/resolving-code-review-comments-with-ml/>,
<https://research.google/blog/ai-in-software-engineering-at-google-progress-and-the-path-ahead/>,
<https://arxiv.org/abs/2507.13499>, <https://arxiv.org/abs/2605.30208>.

### Benchmarks and controlled comparisons

| Source                                                                        | Built from                                                                                                                                                                                               | Metrics                                                                                                     | Finding                                                                                                                                                                                                                                             |
| ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| OpenAI, "A Practical Approach to Verifying Code at Scale"                     | "previously identified issues from the OpenAI codebase" for recall; human evaluation on "recent commits from popular open-source repositories"                                                           | Recall by inference budget; incorrect-comment rate, high-impact comment rate, comments per PR (charts only) | Repository access and code execution made "a stronger reviewer, catching more critical issues and raising fewer false alarms"; "modestly reduced recall in exchange for high signal quality and developer trust"                                    |
| GitHub, "ReviewBench: An open benchmark for AI code review" (2026-10-05)      | 219 PRs from 187 repositories; ground truth from human reviewers, authors' follow-up commits, deterministic tools and several models, judged by an LLM; senior engineers agreed with 96.6% of its labels | Grounded and augmented precision, recall and F1; adjustable Fβ                                              | Offline predicted a 227% rise in critical comments where production saw 262%; "Online experiments remain the ultimate measure of user impact"                                                                                                       |
| Nutanix, CR-Bench, arXiv 2603.11078 (2026-03-10)                              | SWE-bench bugs traced to the PRs that introduced them with `git blame`; not seeded                                                                                                                       | Precision, recall, usefulness rate, signal-to-noise ratio                                                   | A reflection loop raised recall from 27.01% to 32.76% while signal-to-noise fell from 5.11 to 1.95                                                                                                                                                  |
| METR, "Many SWE-bench-Passing PRs Would Not Be Merged into Main" (2026-03-10) | 296 agent PRs reviewed by four maintainers                                                                                                                                                               | Merge decisions against the automated grader                                                                | The grader's scores averaged about 24.2 points above maintainers' merge decisions, the grader's and the maintainers' scores each normalized to the original human-written patches, of which maintainers merged about 68%; unnormalized, 34.9 points |

Sources: <https://alignment.openai.com/scaling-code-verification/>,
<https://github.blog/ai-and-ml/github-copilot/reviewbench-an-open-benchmark-for-ai-code-review/>,
<https://arxiv.org/html/2603.11078v1>,
<https://metr.org/notes/2026-03-10-many-swe-bench-passing-prs-would-not-be-merged-into-main/>.

### What this shows

- **Production signals carry most of the weight.** Each organization above
  reports at least one of: a share of comments acted on, a share of PRs
  commented on, reactions, or incorrect markings. Only Google and Meta
  report randomized or difference-in-differences comparisons.
- **Benchmarks are built from real bugs, not seeded ones.** OpenAI, GitHub
  and CR-Bench draw ground truth from real history: issues people had
  already found, authors' follow-up commits, and for GitHub also tools and
  models.
  No vendor source found measures a reviewer on seeded bugs (UNVERIFIED
  absence). GitHub's augmented metrics exist because a fixed gold set misses
  valid findings its makers did not anticipate.
- **Precision is chosen over recall, deliberately.** OpenAI: "We optimize
  for signal-to-noise first, and only then push recall without compromising
  reliability", and "A system that is slow, noisy, or cumbersome will be
  bypassed." Google tuned AutoCommenter by suppressing rules whose comments
  were not useful.
- **An acted-on rate is not a value measure on its own.** Anthropic: "A
  reviewer that's asked to find problems will always find _something_. If
  you fix every finding, you end up with extra abstraction layers and tests
  for cases that can't happen." OpenAI: stylistic comments "may even incur
  negative utility". AutoCommenter's authors called their offline
  precision and recall noisy, and estimated resolution only after checking
  40 cases by hand.
- **Stacked reviewers.** Anthropic runs several narrowly scoped review agents
  and argues that reviewers that do not share blind spots catch each other's
  mistakes (paraphrase of Clinton), and Code Review deduplicates findings
  from several agents. No source found reports unique findings per reviewer,
  or an ablation of one review pass in a stack (UNVERIFIED absence).
- **Cost and latency are reported beside quality.** Anthropic gives $15–25
  and about 20 minutes a review; GitHub trades 6% more positive feedback
  against 16% more latency; OpenAI gives no figures but says the verifier
  catches many issues "Even at a small fraction of the generator's token
  spend".

## When evals are judged not worth the cost

| Source                                                                                            | Where it holds back                                                                                                                                                                                 | What it recommends instead                                                                                                                                                     |
| ------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Hamel Husain and Shreya Shankar, LLM evals FAQ (page dated 2026-09-18, modified 2026-09-21)       | "Focus automated evaluators on failures that persist after fixing your prompts." On eval-driven development: "Generally no." LLM judges "require 100+ labeled examples, ongoing weekly maintenance" | Error analysis of traces first; "Use a code-based eval when a deterministic rule can identify the failure"; a small team names one domain expert as the quality decision-maker |
| Naresh Jain, "Are Harnesses Worth the Cost?"                                                      | With the frontier model the harness "added overhead without a detected acceptance benefit", at about 7× the cost; his costs exclude the effort of writing the harness                               | For frontier models, an independent acceptance check run once as a final gate rather than continuously (paraphrase)                                                            |
| Böckeler, "TDD inside the agent loop"                                                             | "obviously a very small sample size"; "If anybody has time and tokens to run a larger experiment, that would be very interesting!"                                                                  | Mutation testing, outcome feedback, static analysis, modularity reviews                                                                                                        |
| Böckeler, "Harness engineering"                                                                   | Inferential sensors are "Slower and more expensive"; LLM checks run "expensively and probabilistically. Not on every commit."                                                                       | Computational sensors such as mutation and structural tests, "underused in the past"                                                                                           |
| OpenAI, "Testing Agent Skills Systematically with Evals"                                          | "add slower, heavier checks only when they reduce risk"                                                                                                                                             | Fast deterministic checks over traces first                                                                                                                                    |
| Anthropic, "Demystifying evals for AI agents"                                                     | Evals "may even seem like overhead that slows down shipping", but "Evals get harder to build the longer you wait"                                                                                   | Layers of the "Swiss Cheese Model": production monitoring, A/B tests, user feedback, manual transcript review, human studies                                                   |
| Anthropic, "Building effective agents" (2024-12-19)                                               | Add complexity "_only_ when it demonstrably improves outcomes"                                                                                                                                      | "finding the simplest solution possible"                                                                                                                                       |
| Anthropic, Claude Code best practices                                                             | "If any other advice on this page ever starts to feel like busywork, that's probably a sign it belongs in this table too."                                                                          | Add to CLAUDE.md what was corrected twice; make unbendable rules hooks or deny rules                                                                                           |
| OpenAI, Codex best practices                                                                      | A common mistake is "Scheduling a recurring task before it's reliable manually."                                                                                                                    | Run a workflow by hand until it is predictable                                                                                                                                 |
| Thoughtworks Radar Vol. 35, feedback flywheel (_Trial_) and human-in-the-loop theater (_Caution_) | The flywheel should also remove outdated rules and noisy sensors (paraphrase); a human approval step can become "an empty approval step rather than a real check"                                   | Retrospective harness edits each session; risk-tiered human review, with mutation testing and property-based testing elsewhere (paraphrase)                                    |
| METR, "uplift update" (2026-02-24)                                                                | Selection effects made its new experiment's data "an unreliable signal of the current productivity effect of AI tools"                                                                              | Observational data such as transcripts, questionnaires, fixed-task experiments                                                                                                 |

Sources: <https://hamel.dev/blog/posts/evals-faq/>,
<https://martinfowler.com/articles/are-harnesses-worth-the-cost.html>,
<https://martinfowler.com/articles/exploring-gen-ai/tdd-in-the-agent-loop.html>,
<https://martinfowler.com/articles/harness-engineering.html>,
<https://developers.openai.com/blog/eval-skills>,
<https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents>,
<https://www.anthropic.com/engineering/building-effective-agents>,
<https://code.claude.com/docs/en/best-practices>,
<https://learn.chatgpt.com/guides/best-practices>,
<https://www.thoughtworks.com/radar/techniques/feedback-flywheel>,
<https://www.thoughtworks.com/radar/techniques/human-in-the-loop-theater>,
<https://metr.org/blog/2026-02-24-uplift-update/>.

No source found gives a threshold of team size below which evals stop
paying, or addresses solo projects (UNVERIFIED absence). What the sources
share: evaluate failures that were observed, not imagined; prefer a
deterministic check when one can decide; size the effort to the risk; and
treat production observation, read transcripts and incident history as
evidence alongside evals.

## Corrections to ai-development.md

Applied to that file on 2026-11-09.

- **METR (2026-02-24).** `ai-development.md` says METR "now calls its own
  earlier slowdown data 'an unreliable signal'". The post says so of the
  data "from our new experiment", the one started in August 2025, not of the
  earlier study.
- **Gloaguen et al.** `ai-development.md` says LLM-generated context files
  "slightly lowered task success". The v1 abstract says "context files tend
  to reduce task success rates" for both LLM-generated and
  developer-committed files; v3, revised 2026-09-29, says they do "not
  generally improve task success rates". The cost of "over 20%" holds.
- **Böckeler on TDD.** The token multiples in her appendix are 8.50×, 2.96×
  and 4.89×, so "3–8.5×" slightly overstates the low end; her heading says
  "At least 3x". The article page prints no date; 2026-08-10 is the date in
  the series index.
- **Codex and AGENTS.md.** "add rules only after repeated mistakes" is cited
  to the Codex AGENTS.md page, which as read on 2026-11-09 says nothing about
  when to add rules. The Codex best-practices guide says it: "When Codex
  makes the same mistake twice, ask it for a retrospective and update
  `AGENTS.md`."
- **"Managed Code Review".** Anthropic's documentation names the product
  "Code Review" and describes it as "a managed service"; "Managed" is
  `ai-development.md`'s word, not the product's name.

## What pulsar takes from this

Everything below was written as a proposal for the maintainer to decide.

**Decided on 2026-11-09.** pulsar is a reference implementation that shows
current practice, so practices the sources already establish are cited and
used rather than measured again. In particular:

- **The review replay is not run.** Its cost, 180 reviews and the
  maintainer's labeling, is more than a reference implementation warrants.
  `docs/harness.md` cites the vendor practice behind the three reviews and
  records running all three, in order, as the maintainer's decision.
- **#3 closes without an ablation runner.** Skills and subagents written
  here are still evaluated, as `right-sizing` is; `AGENTS.md` is not
  ablated, and the study above is cited instead.
- **#4 becomes a "Reviews" section in each pull request's description**:
  what each review found, fixed and left unchanged, and the maintainer's
  review time. Cost and turns are not recorded, and the wrapper for
  unattended runs waits until there is one (#67).
- **#5 stays as planned**: a measurement, not a gate.
- **The Evidence column of `docs/harness.md`** names the kind of evidence
  for each control, as the last table below proposes, except that
  `AGENTS.md` and the three reviews are not evaluated either.

The proposals below are kept as written; where they differ, this list
decides.

### The three review controls

_Not adopted; see the decisions above._

`docs/harness.md` then kept them "only if the ablation shows each one finds
problems the others miss". That is a question about unique findings, and the
sources give no published method for it (above), so pulsar would have to
build one from the methods that exist: production dispositions, ground
truth drawn from several sources (ReviewBench), and replaying a reviewer on
a past PR (`claude-code-security-review`'s eval tool).

**What the repository's history holds.** Of the 21 merged PRs from #34 to
#65, 20 carry 151 top-level inline review comments between them, all under
the maintainer's account, so the account does not say which tool or person
wrote each. Most threads have a reply that begins "Fixed" or "Not changed",
which records a disposition. The two pre-PR reviews leave only commits,
titled "address the review of X" before #54 and "address the code review
of X" from #54 on. One of those commits has an empty body (`d162308`), and
only one body (`23e3681`) records the security review's result: "The
security review found nothing to change."

**What a retrospective tally of that history can show.** The reviews run in
order, and each later review sees code that the earlier ones already fixed.
So a tally can show:

- what the third review found that survived both earlier reviews, a lower
  bound on its value given the other two (the bundled `/code-review`, not
  the `code-review` plugin this survey named; see
  `docs/research/code-review-tools.md`);
- how often its findings were fixed rather than declined, an addressed rate
  comparable in form with OpenAI's 52.7% and GitHub's addressed rate.

It cannot show:

- whether anything the first review found would also have been found by the
  second or third, so it cannot show that the first review finds problems
  the others miss, nor that the later ones are redundant with it;
- which of the first two reviews found a given problem, since both feed one
  commit whose body is sometimes empty;
- whether a fixed finding mattered: the agent that wrote the code also
  resolved the threads, under a ruleset that requires every thread resolved,
  and Anthropic warns that fixing every finding adds code for cases that
  cannot happen.

So the tally alone is not an adequate method for the rule in
`docs/harness.md`. It is a cheap first look at the third review's marginal
value, and its labels are reusable below.

**A replay on past snapshots.** The history keeps the commit each PR had
before its first review commit, the code the first reviewer saw. Running
all three reviewers on that same code removes the ordering. A proposed
procedure:

1. For each of those 20 PRs, check out that commit and run each of the
   three reviewers on it independently, each in a fresh session, with
   `code-review@claude-plugins-official` run without `--comment` so nothing
   is posted. Three runs per reviewer, since one run of a non-deterministic
   agent "tells you little" (`claude plugin eval` documentation). Turn off
   Claude Code's updates and pin the model, as `make eval` does.
2. Pool every finding into one list per PR and merge duplicates, as
   ReviewBench pools reviewers, follow-up commits and tools into one ground
   truth. Findings that match a past "Fixed in" or "Not changed" reply, or a
   change in a review commit, start with that label.
3. The maintainer labels each remaining finding, pass or fail, as Husain and
   Shankar recommend: valid and worth fixing before merge (Code Review's
   "Important"), valid but minor ("Nit"), or wrong.
4. Report per reviewer: valid findings, valid findings no other reviewer
   raised in any run, precision (valid over reported), Important findings
   only it raised, its cost from `total_cost_usd` (#4) and its time. A finding
   raised in one run of three and one raised in all three are reported
   apart, as pass@k and pass^k are.
5. Read the transcripts of a sample, as Anthropic advises, before trusting
   the counts.

Twenty PRs is within the 20–50 tasks Anthropic calls "a great start". The
cost is not known in advance: 20 PRs, three reviewers and three runs is 180
reviews. Anthropic's advice for Code Review is to "run a small pilot to
estimate monthly spend"; the same applies here, on three PRs first.

**A decision rule to consider.** Keep a reviewer that raises valid
Important findings no other reviewer raises; drop or narrow one whose valid
findings are all raised by another. `/security-review` may find little on
most PRs and still be kept for a rare severe catch: Anthropic's published
evidence for its security review is two catches by the GitHub action and
an account of its own process, not a rate. If it is kept on those
grounds, the Evidence column can say so as the maintainer's decision.

### Issue #3

_Not adopted beyond what the decisions above keep._

#3 proposes running the real CLI against a copy of the repository with and
without each control. The sources suggest narrowing it:

- **First, the review replay above.** It needs no new feature work, which
  #3 says it waits for, and it answers the one rule in `docs/harness.md`
  that names an ablation.
- **Then `AGENTS.md`, with and without.** It is the one guide here whose
  value only an eval can show, and Gloaguen et al. found context files as a
  whole did not generally help while costing more. Tasks can be rebuilt from
  merged PRs: start at the PR's base, give the issue, and score with the
  PR's tests, `make verify` and `make conformance`, which the agent does not
  see. METR's 24-point gap between tests passing and maintainers merging
  says a maintainer's judgment of mergeability belongs beside the tests.
  Naresh Jain's lesson applies too: record the model and the cost with the
  pass rate.
- **No agent evals of hooks and gates.** No source evaluates them that way;
  their evidence is their own tests and what they catch (below).
- **When to rerun.** Thoughtworks recommends a schedule; the plugin-eval
  documentation names changing the plugin or "a new model is released" as
  reasons. For a project with no CI agents yet (#1), rerunning on a model or
  harness change would likely cost less than a nightly run.

### Issue #4

_Adopted in part; see the decisions above._

The ledger is pulsar's production monitoring in Anthropic's "Swiss cheese"
sense, the layer the review vendors above report most of their figures
from. Proposals:

- `claude -p --output-format json` reports `total_cost_usd`, a client-side
  estimate, and a session ID (headless documentation). Whether it reports
  `num_turns` is still **UNVERIFIED**, as #4 says.
- Beside cost and turns, record per run what the vendors record per review:
  findings per review control, how many were fixed and how many declined,
  and whether the maintainer asked for changes after the reviews, as
  GitHub's `total_merged_no_human_change_request_after_review` does. Record
  the maintainer's review time, which #4's ExecPlan fields already name.
- All feature work so far has been interactive, so a ledger kept only for
  unattended runs would still be empty. One line per pull request,
  interactive or not, would start the record now.

### Issue #5

Mutation testing is in _Adopt_ on Radar Vol. 35 as a guardrail for
AI-written tests, with the advice to target specific packages or run
incrementally because full runs are slow. Böckeler used mutation score to
compare TDD with no TDD. `go-gremlins/gremlins` is at v0.6.0 (2025-12-06);
its README says it is "still in its 0.x.x release" and "doesn't work very
well on very big Go modules, mainly because a run can take hours". So the
plan in #5 fits the sources: a measurement on the security-critical
packages, recorded per package, not a gate. It is also a deterministic
measure of what `repocheck` cannot see, and the strength of the hidden
checks #3's tasks would be scored with.

### Controls that need no eval, and what their Evidence column could say

_Adopted except for the `AGENTS.md` and review rows; see the decisions
above._

| Controls in `docs/harness.md`                                                                                                                          | Eval needed?             | Proposed evidence                                                                                                                                                 |
| ------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Prettier and markdownlint, `shellcheck` and `shfmt`, `zizmor`, `misspell`, `golangci-lint`, `sqlc diff`, `make dockerfile-check`, Conventional Commits | No                       | What justified each (incident, review finding, maintainer's decision), plus its first recorded catch, answering Böckeler's question whether a silent sensor works |
| PostToolUse `format.sh`, Stop `stop-check.sh`                                                                                                          | No                       | Their tests in `internal/harness` (the Stop hook has them; the format hook has none) and the incidents already recorded                                           |
| `make check` / `make verify`, `main` ruleset, `make conformance`                                                                                       | No                       | The maintainer's decision, as the definition of done and its enforcement; for conformance, the suite's exported results                                           |
| `repocheck`                                                                                                                                            | No                       | Its own tests; #5 measures the strength of the tests it counts                                                                                                    |
| Sandbox, permission rules, `make setup` / `make tools`                                                                                                 | No                       | Vendor practice with its source (`docs/research/ai-development.md`) and the observed behavior already recorded under Deliberate weakenings                        |
| `right-sizing`                                                                                                                                         | Done                     | Unchanged                                                                                                                                                         |
| `AGENTS.md`                                                                                                                                            | Yes, as a whole (#3)     | Until then, each line traceable to the mistake, review finding or authority behind it, the vendors' "same mistake twice" rule                                     |
| The three review controls                                                                                                                              | Yes, by the replay above | Until then, "Pending ablation"; for the two third-party ones, also the trust decision Anthropic asks for: source, the frozen marketplace, and what they run       |
| The maintainer merges every pull request                                                                                                               | No                       | The maintainer's decision; #4's review time shows whether it is a real check rather than what Thoughtworks calls "human-in-the-loop theater"                      |

"Hypothesis" in the Evidence column then covered both controls whose function
is verified but whose value to the agent is unmeasured and controls with no
check at all. Splitting it into the kinds of evidence the sources use
(tested, catches, incident, vendor practice, maintainer's decision, eval)
would say which is which.
