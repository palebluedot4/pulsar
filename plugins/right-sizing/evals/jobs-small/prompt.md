---
description: Small scale on an existing database, asked plainly; a message broker cluster is over-engineering.
tags: [decide, small]
max_turns: 40
timeout_seconds: 900
allowed_tools: [Read, Glob, Grep, Write, WebSearch, WebFetch, Agent, Skill]
---

We are an early-stage SaaS with two engineers. Our Go service runs on one
managed PostgreSQL database. We need background jobs: sending emails,
generating PDF reports and calling webhooks, about 50,000 jobs a day with a
peak of perhaps 20 a second. Jobs must not be lost and should be retried on
failure. We have no operations team. How should we run background jobs?
