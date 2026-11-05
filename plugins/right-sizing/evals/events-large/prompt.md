---
description: Large scale, asked plainly; a database-backed queue is under-provisioned and a streaming platform is warranted.
tags: [decide, large]
max_turns: 40
timeout_seconds: 900
allowed_tools: [Read, Glob, Grep, Write, WebSearch, WebFetch, Agent, Skill]
---

We are a company of about 40 engineering teams running roughly 200 services.
They exchange business events: about 300,000 events a second on average and
1,000,000 at peak. Several teams must consume the same events independently,
events must be replayable for 30 days, and per-entity ordering matters. We
have a platform team of eight engineers and run on a major public cloud. How
should our services exchange these events?
