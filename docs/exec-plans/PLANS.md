# ExecPlans

An ExecPlan is the plan for a piece of work an agent runs without a human in
the loop. It follows OpenAI's ExecPlan format
(<https://developers.openai.com/cookbook/articles/codex_exec_plans>) and opens
with the questions Anthropic asks before leaving a task unattended
(<https://code.claude.com/docs/en/best-practices>).

Plans being worked live in `active/`; finished ones move to `completed/`
with their Outcomes filled in. Both are created with the first plan. Name a plan after its work:
`active/authorization-code-flow.md`.

A plan is self-contained: a reader who has seen nothing else in the
repository can follow it. The agent keeps it current as it works and
proceeds from milestone to milestone without asking what to do next.

## Template

```markdown
# <Work, in a few words>

Issue: #<n>

## Before starting

- **Done means:** <observable behavior, e.g. "`oidcc-basic-certification-test-plan` passes">
- **Checked by:** <the command that decides it, e.g. `make verify`>
- **May touch:** <paths and services; everything else is off limits>
- **Stops at:** `--max-turns <n>`, `--max-budget-usd <n>`, or <condition>
- **Signed off by:** <who reviews the result>
- **Versions:** Claude Code <version>; model <id>; plugins <name@sha, …>

## Purpose

<Why this work matters and what a user can do afterwards.>

## Milestones

1. <Each one ends in something that can be demonstrated.>

## Progress

- [ ] <Kept current; timestamps for completed items.>

## Surprises & discoveries

<What turned out differently, with evidence.>

## Decision log

- <Decision, the reason, the date.>

## Outcomes & retrospective

- **Result:** <done / partial / abandoned, against "Done means">
- **Turns:** <n> **Cost:** <USD> **Wall clock:** <duration>
- **Human review time:** <minutes>
- **Defects found afterwards:** <list, with links>
- **Harness changes this run calls for:** <link to the docs/harness.md changelog>
```
