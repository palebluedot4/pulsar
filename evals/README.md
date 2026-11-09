# Evals

Evidence that a skill or subagent written here helps, rather than merely
exists.
The method follows Anthropic's guidance
(<https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents>,
<https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices>):

1. **Scenarios first.** Write at least three scenarios, drawn from real
   tasks or failures, before writing the skill or subagent they test.
2. **Baseline.** Run the scenarios without it. A result
   only means something next to its baseline.
3. **Grade outcomes, not paths.** Each scenario states what a good result
   contains, checkably.
4. **Repeat.** Agents are not deterministic; run each scenario several times
   and report how many of the runs passed, from which pass@k (any run
   passed) and pass^k (every run passed) can be read.
5. **Ablate.** For a skill or subagent already in place, remove it and
   rerun; one that changes nothing is a candidate for removal.
6. **Read the transcripts.** A pass for the wrong reason is a failure.

Every result records the date, Claude Code version, model IDs and the
commits on `main` it ran against. `make eval` turns Claude Code's
auto-updates off for the run (`docs/harness.md`).

## Where evals live

- **Skills**, and any subagent written here, are packaged as plugins under
  `plugins/`, and their cases live in the plugin's own `evals/`, because
  `claude plugin eval` loads only the plugin under test. Run them with
  `make eval PLUGIN=<name>`, which pins the models and a cost ceiling and
  compares runs with and without the plugin. Raw runs land in the plugin's gitignored
  `evals/results/`; a short `results.md` beside the cases records what each
  run showed.
- **Repository controls** (`AGENTS.md`, hooks, gates) cannot be evaluated
  that way, since the plugin evaluator loads no project configuration. They
  are not evaluated at all: each names other evidence in `docs/harness.md`,
  as the maintainer decided after `docs/research/evals.md`.
