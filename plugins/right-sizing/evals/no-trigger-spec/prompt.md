---
description: Phrased like a decision, but a specification settles it; the skill must not fire.
tags: [guard, no-trigger]
max_turns: 10
timeout_seconds: 300
allowed_tools: [Read, Glob, Grep, Skill]
---

We are building an OAuth 2.0 authorization server. How should our token
endpoint respond when the PKCE code_verifier doesn't match the
code_challenge from the authorization request?
