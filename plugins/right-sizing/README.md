# right-sizing

A Claude Code skill for technical and project decisions: establish the
project's real scale, research current practice from dated primary sources,
keep what fits, decide, and record the research.

It was written evaluation-first. Eight of the nine cases in `evals/` came
before the skill; the ninth was added after a review, and `evals/results.md`
says so. That file records what the baseline did without it and what the
skill changes. Without it, models asked a plain "which should we use?"
answered from training data and did no research.

This repository is its own plugin marketplace, so another project can use
the skill as released on `main`:

```text
/plugin install right-sizing --marketplace palebluedot4/pulsar
```

Inside this repository it is enabled in `.claude/settings.json` and installed at
project scope by `make setup`; enabling it alone did not load it (#68). A new
version reaches users when `version` in `.claude-plugin/plugin.json` is bumped
on `main`; until then they keep the version they have.

Run the evals from the repository root with `make eval PLUGIN=right-sizing`.

The interview round borrows its shape, one round of questions each with a
recommended default, from Matt Pocock's `grilling` skill
(<https://github.com/mattpocock/skills>). The skill is self-contained because
`claude plugin eval` loads only the plugin under test.
