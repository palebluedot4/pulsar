# right-sizing

A Claude Code skill for technical and project decisions: establish the
project's real scale, research current practice from dated primary sources,
keep what fits, decide, and record the research.

It was written evaluation-first. The cases in `evals/` came before the skill,
and `evals/results.md` records what the baseline did without it and what the
skill changes. Without it, models asked a plain "which should we use?"
answered from training data and did no research.

Run the evals from the repository root with `make eval PLUGIN=right-sizing`.

The interview round borrows its shape, one round of questions each with a
recommended default, from Matt Pocock's `grilling` skill
(<https://github.com/mattpocock/skills>). The skill is self-contained because
`claude plugin eval` loads only the plugin under test.
