# Shared state: whether OpenID Providers need Redis

Surveyed 2026-11-05 from official documentation and release notes. Anything
not confirmed is marked **UNVERIFIED**.

| Product        | Redis                                                                                                                                                            | Source                                                                                                      |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| authentik      | Removed in 2025.10; caching, the embedded outpost and WebSocket traffic moved to PostgreSQL, after session storage (2025.4) and locks (2024.6)                   | <https://goauthentik.io/blog/2025-11-13-we-removed-redis/>, <https://docs.goauthentik.io/releases/2025.10/> |
| Zitadel        | Optional cache connector, off unless enabled; in-memory and database-backed connectors are the alternatives; Redis recommended for multi-node cache invalidation | <https://zitadel.com/docs/self-hosting/manage/cache>                                                        |
| Authelia       | Recommended for highly available deployments, because the default session store is in memory                                                                     | <https://www.authelia.com/configuration/session/redis/>                                                     |
| Keycloak       | Not used; user sessions are persisted in its database by default since Keycloak 26, with embedded Infinispan as a cache                                          | UNVERIFIED in this survey                                                                                   |
| Ory Hydra, Dex | Not used                                                                                                                                                         | UNVERIFIED in this survey                                                                                   |

## Conclusion

No surveyed provider requires Redis. Where it appears, it is an optional
cache (Zitadel) or a shared session store for a product whose default store
is in memory (Authelia). authentik, which did require it, replaced it with
PostgreSQL. pulsar's design keeps Login Sessions in PostgreSQL (#11), so
neither reason applies.
