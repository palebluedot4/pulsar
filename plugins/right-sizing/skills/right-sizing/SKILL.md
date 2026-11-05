---
name: right-sizing
description: Makes a technical or project decision from current, dated primary sources, sized to the project's real scale, and records the research. Use it before answering, not as an offer afterwards, whenever the user asks which technology, tool, library, architecture or practice to use, how they should build, run or implement something, or what the best practice or industry standard is, even when the question is short and the answer seems familiar; also when starting a project or a major technical decision.
---

# Right-sizing

Training data goes stale and "best practice" is always best for some scale.
Decide from what is true now, for this project's size.

## 1. Establish the context

The decision turns on scale and constraints: users, traffic and data volume;
team size and skills; budget; existing stack; compliance; timeline.

- If the user has stated them, do not ask again. Assume what is missing,
  and state the assumption.
- If they are unknown and would change the answer, ask before recommending.
  Ask everything in one round, and give your assumed default for each
  question so the user can accept it with a word.

## 2. Research current practice

Do not answer from memory, however familiar the question, and do not answer
first and offer to verify afterwards.

- Use search to find primary sources, then fetch and read each page the
  decision rests on: official documentation, specifications, project
  repositories and release notes, vendor pricing pages. A search snippet is a
  lead, not a source; a decision resting only on search results has not been
  researched.
- Authorities rank: specifications and official documentation, then
  maintainers and vendors, then respected practitioners. Secondary posts only
  point to primary sources. If the repository's `AGENTS.md` or `CLAUDE.md`
  names an order of authorities, follow it.
- For each practice, note the scale it was designed for: who uses it, and at
  what size.
- Research independent questions in parallel when subagents are available.

## 3. Fit, then decide

- Keep what fits the context. Reject the rest with a reason tied to that
  context, whether it is too heavy or too light. When asked for the industry
  standard, say which size of organization a practice is standard for.
- Decide wherever evidence decides. Ask the user only about taste or values,
  with one recommendation each. Do not hand back a menu.

## 4. Record

Save the research to `docs/research/<topic>.md`, or wherever the repository
already keeps research:

```markdown
# <Topic>

Surveyed <YYYY-MM-DD>. Context: <the scale and constraints decided on>.

## Findings

- <Claim>. [<Source title>](url), <publication or access date, YYYY-MM-DD>,
  <primary or secondary>.
- <Claim that could not be confirmed>. UNVERIFIED.

## Decision

<What, why it fits, what was rejected and why, and the scale at which the
decision should be revisited.>
```

End the reply with the decision, why it fits, the rejected options with
their reasons, and what change in scale would change the decision. If the
repository records decisions as ADRs, name the decision that merits one.
