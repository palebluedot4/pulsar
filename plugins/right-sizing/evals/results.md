# Results

Summaries of eval runs; raw output is in the gitignored `results/`. The
skill is evaluated on the models it is used with, `claude-opus-5-5` and
`claude-sonnet-5-5`.

Every cost below is the evaluator's estimate at API list prices. The runs
used a Claude plan login, not an API key, so they drew on the plan's usage
rather than being billed; the estimates still compare runs with each other.

## How the cases were chosen

Exploratory baseline runs on `claude-sonnet-5-5`, with no skill, on
2026-11-05 shaped the cases:

- **Asked to research, the model already does it well.** The first decision
  prompts told the model to research and save its sources. It did, separated
  primary from secondary sources and flagged what it could not verify, and
  it sized every decision to the stated context, including under explicit
  pressure for big-company practice. Those prompts handed the baseline the
  procedure the skill exists to supply, so they could not measure the skill.
- **Asked plainly, it does not research at all.** Given a bare question
  ("which migration tool should we use?", "what should we use for login?"),
  no run fetched or searched anything; answers came from training data, and
  said so ("I haven't … confirmed the latest versions"). Nothing was
  recorded. That is the gap the skill targets.

So the decision cases ask plainly, with the project's scale stated, and are
graded on behavior: current sources fetched, research saved with dated and
linked sources, and a decision that fits. Right-sizing judgment and asking
for missing context, which the baseline already does, are kept as guards the
skill must not break. Two cases where the skill must not fire, a bug fix and
a conceptual explanation, check that its description does not reach too far.

| Case                     | Role                                                    |
| ------------------------ | ------------------------------------------------------- |
| `login-small`            | Gap: plain question, small scale                        |
| `jobs-small`             | Gap: plain question, small scale                        |
| `events-large`           | Gap: plain question, large scale (heavy is right)       |
| `best-practice-pressure` | Gap: plain question, small scale under big-company pull |
| `login-asks-scale`       | Guard: asks for missing context before deciding         |
| `decides-not-menus`      | Guard: decides instead of returning a menu              |
| `no-trigger-bug`         | Guard: skill must not fire on a bug fix                 |
| `no-trigger-explain`     | Guard: skill must not fire on a conceptual question     |

The cases were not changed after the skill was evaluated. The skill was: its
description now says to use it before answering rather than offer it
afterwards, and its research step requires fetching the pages a decision
rests on. Both changes followed earlier runs on these same cases, in which
Haiku, a model the skill no longer targets, answered from memory and then
offered the skill, and once searched without reading any page. So the
trigger rate below was measured on the cases the description was adjusted
against; it is not evidence that the description generalizes.

## 2026-11-05: skill 0.1.0, with and without

- **Setup:** cases as committed in `d0d09ba`, skill as committed in
  `6e479ee`; Claude Code 2.1.318; `--ablation with-without`; three runs per
  arm; agent `claude-sonnet-5-5`, then `claude-opus-5-5`; judge
  `claude-sonnet-5-5` for both.
- **Estimated cost and time of the whole suite:** Sonnet 4.32 USD,
  1,200 s; Opus 7.92 USD, 1,673 s.

Both models gave the same pattern, so one table holds for each:

| Grader                               | Without skill | With skill |
| ------------------------------------ | ------------- | ---------- |
| `researched` (fetched sources)       | 0/12          | 12/12      |
| `research-saved`                     | 0/12          | 12/12      |
| `dated-sources`                      | 0/12          | 12/12      |
| `linked-sources`                     | 0/12          | 12/12      |
| `right-sized`                        | 12/12         | 12/12      |
| `asks-before-deciding`, `decides`    | 6/6           | 6/6        |
| `skill-not-fired` (bug, explanation) | 6/6           | 6/6        |
| `fixes-bug`, `explains`              | 6/6           | 6/6        |
| `skill-fired` (decision questions)   | —             | 18/18      |

**What changed.** Without the skill, neither model researched a plainly
asked decision; with it, every run fetched primary sources and saved dated,
linked research, on both models. Nothing regressed: decisions stayed sized to
their context, and the skill fired on every decision question and on neither
the bug fix nor the conceptual question. Mean delta 0.40 on both.

**What it costs, per run of a decision case.** Averages from the four gap
cases:

| Model  | Without skill          | With skill             |
| ------ | ---------------------- | ---------------------- |
| Sonnet | 0.04–0.05 USD, 16–21 s | 0.16–0.29 USD, 52–61 s |
| Opus   | 0.08–0.12 USD, 19–37 s | 0.24–0.51 USD, 61–91 s |

About four to five times the cost and three times the time of an answer from
memory. Where it did not fire, the cost was unchanged.

**What was read, not just scored.** An Opus research file for `jobs-small`
cites PostgreSQL's documentation for `FOR UPDATE SKIP LOCKED`, River's own
documentation for its retry policy and benchmarks, and River's releases for
its pre-1.0 status, each with an access date and marked primary, and notes
that River does not claim exactly-once delivery.

**Limits.** Three runs per arm; eight synthetic cases; one judge model, whose
agreement with human judgement has not been measured. The gap cases check
that research happened and was recorded, not that every cited fact is right.
The trigger rate comes from cases the description was adjusted against (see
above).

**Added since.** A review found the two cases where the skill must not fire
too far from its trigger: the riskiest phrase in the description is "how they
should build, run or implement something", and most of this project's work
is questions a specification answers. `no-trigger-spec` asks how a token
endpoint should respond to a PKCE mismatch, which RFC 7636 settles. It was
added after the run above.

## 2026-11-05: skill 0.1.0 on the near-miss case

- **Setup:** as above, `--case no-trigger-spec` only.
- **Estimated cost:** Sonnet 0.45 USD; Opus 0.74 USD.

| Grader              | Sonnet, without | Sonnet, with | Opus, without | Opus, with |
| ------------------- | --------------- | ------------ | ------------- | ---------- |
| `answers-from-spec` | 3/3             | 3/3          | 3/3           | 3/3        |
| `skill-not-fired`   | 3/3             | **0/3**      | 3/3           | **2/3**    |

The skill misfired on a question a specification answers: on Sonnet every
time, on Opus once. The answers stayed right (`invalid_grant`), but the runs
cost about three times as much (Sonnet 0.34 against 0.11 USD), and most of
this project's work is questions of this kind. The runs' workspaces were not
kept, so what the skill did once it fired is unknown.

**Change, skill 0.2.0.** The description now applies when the user must
choose between real options, and excludes questions a specification,
standard or existing code already answers, and conceptual explanations; the
body says the same. Every case, not only this one, has to be run again.
