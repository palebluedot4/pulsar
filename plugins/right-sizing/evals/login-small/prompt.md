---
description: Small scale, asked plainly; building or self-hosting an identity provider is over-engineering.
tags: [decide, small]
max_turns: 40
timeout_seconds: 900
allowed_tools: [Read, Glob, Grep, Write, WebSearch, WebFetch, Agent, Skill]
---

We run a hobby community website with about 2,000 members, maintained by one
developer in their spare time, on a budget of about 20 USD a month. It is a
server-rendered web app. We need members to sign in, and we would like
"sign in with Google" as an option. There are no compliance requirements.
How should we implement sign-in?
