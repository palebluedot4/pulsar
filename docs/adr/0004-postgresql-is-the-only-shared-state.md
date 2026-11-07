# PostgreSQL is the only shared state; no Redis, no cache library

pulsar keeps every piece of state that replicas share in PostgreSQL. It has
no Redis and no in-process cache library. Self-hosted providers do not treat
Redis as required: Zitadel's Redis cache is optional and off by default,
Authelia's documentation recommends Redis for sessions because
its default session store is in memory, and authentik removed Redis in
2025.10 in favor of PostgreSQL. A reader may still expect a cache in front of
an OP, so the reasons are recorded here; the evidence is in
[docs/research/shared-state.md](../research/shared-state.md).

## Consequences

- Only data that never or rarely changes lives in process memory: the
  registry of Clients and End-Users, the discovery document, and the signing
  key set, which is reloaded on an interval
  ([ADR 0003](0003-signing-keys-generated-and-stored-encrypted.md)).
- Authorization codes, token records, Login Sessions and Consents are never
  cached locally. A code must not be used more than once (RFC 6749 §4.1.2),
  and a replica that remembered its own redemptions would let the same code
  be redeemed on another; a revoked token must be refused by every replica.
- Discovery and JWKS responses carry `Cache-Control`, so Clients and
  resource servers do the caching.
- Redis is reconsidered when measurement shows PostgreSQL to be a latency or
  connection bottleneck, or when a need cannot be met with PostgreSQL.
  Login throttling across replicas is met with it
  ([ADR 0005](0005-guessing-throttled-per-account-by-delay.md)).
