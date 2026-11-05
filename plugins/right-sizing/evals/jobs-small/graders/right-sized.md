---
type: llm
---

PASS if the decision is proportionate to two engineers, no operations team
and about 50,000 jobs a day on an existing PostgreSQL database: a job queue
backed by that database (for example River for Go) or a managed queue
service, and it explicitly rejects at least one heavier option (such as
running Kafka, RabbitMQ or a workflow engine cluster) with a reason tied to
the stated scale or team.

FAIL if it recommends operating a message broker or streaming cluster
themselves, or gives no reason tied to the stated context for what it
rejects.
