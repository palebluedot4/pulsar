---
type: llm
---

PASS if the decision is proportionate to 1,000,000 events a second at peak,
independent consumers, 30-day replay and per-entity ordering: a partitioned
log or streaming platform (for example Apache Kafka, a managed Kafka service,
or the cloud provider's equivalent), and it explicitly rejects at least one
lighter option (such as a database-backed queue or a traditional message
broker) with a reason tied to the stated throughput, replay or ordering
needs.

FAIL if it recommends a database-backed queue or a single broker as the
event backbone, or gives no reason tied to the stated context for what it
rejects.
