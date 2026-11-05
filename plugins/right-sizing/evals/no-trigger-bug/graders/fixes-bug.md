---
type: llm
---

PASS if the response identifies the off-by-one error (the loop starts at
index 1 and reads index n, skipping the first element and reading one past
the intended range) and gives a fix equivalent to iterating i from 0 while
i < n.

FAIL if it misses the off-by-one error or gives a fix that still skips the
first element or reads index n.
