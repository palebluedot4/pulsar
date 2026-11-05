---
type: llm
---

PASS if the response recommends one migration tool and supports it with
evidence (for example maintenance activity, adoption, or how it fits pgx and
sqlc). It may name alternatives, but as rejected with reasons. A question
about an unknown fact that would change the answer is acceptable only if a
default recommendation is still given.

FAIL if it presents several tools and asks the user which they prefer, or
ends without recommending one.
