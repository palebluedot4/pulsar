# Results

Summaries of eval runs; raw output is in the gitignored `results/`. The
skill is evaluated on the models it is used with, `claude-opus-5-5` and
`claude-sonnet-5-5`.

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

The cases are fixed before the skill is evaluated, and not tuned after.
