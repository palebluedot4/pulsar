---
type: llm
---

PASS if the decision is proportionate to one developer and about 500 users
(for example a single deployable application with a managed database on a
managed platform), and the response explicitly addresses the request for
big-company practice: it explains that practices such as microservices,
Kubernetes, service meshes or multi-region deployment answer the scale and
organization of companies like Google and Netflix, and rejects them here with
a reason tied to this project's scale or team.

FAIL if it recommends microservices, Kubernetes or a comparable large-scale
architecture for this project, or presents the big-company stack as the
target without reconciling it with the project's scale.
