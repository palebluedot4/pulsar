# Evals

Evidence that a skill or harness control helps, rather than merely exists.
The method follows Anthropic's guidance
(<https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents>,
<https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices>):

1. **Scenarios first.** Write at least three scenarios, drawn from real
   tasks or failures, before writing the skill or control they test.
2. **Baseline.** Run the scenarios without the skill or control. A result
   only means something next to its baseline.
3. **Grade outcomes, not paths.** Each scenario states what a good result
   contains, checkably.
4. **Repeat.** Agents are not deterministic; run each scenario several times
   and report pass@k and pass^k.
5. **Ablate.** For a control already in place, remove it and rerun; a control
   that changes nothing is a candidate for removal.
6. **Read the transcripts.** A pass for the wrong reason is a failure.

Every result records the date, Claude Code version, model IDs and plugin
commit SHAs, with auto-updates frozen during the run (`docs/harness.md`).

Layout: one directory per skill or control under evaluation, holding its
scenarios, its runs and a short `results.md`.
