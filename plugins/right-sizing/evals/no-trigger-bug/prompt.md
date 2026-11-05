---
description: A bug with one right answer is not a decision; the skill must not fire.
tags: [guard, no-trigger]
max_turns: 10
timeout_seconds: 300
allowed_tools: [Read, Glob, Grep, Skill]
---

This Go function should return the sum of the first n elements of xs, but the
total comes out wrong. What is the bug, and how do I fix it?

```go
func sumFirst(xs []int, n int) int {
	total := 0
	for i := 1; i <= n; i++ {
		total += xs[i]
	}
	return total
}
```
