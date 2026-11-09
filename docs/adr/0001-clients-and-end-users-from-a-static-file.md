# Clients and End-Users come from a static file

pulsar reads its Clients and End-Users from a declarative file at startup, as
Dex does with `staticClients` and `staticPasswords`. It has no admin API,
CLI, or Dynamic Client Registration for them. PostgreSQL holds only state
that pulsar creates while running, such as signing keys, authorization
codes, token records, Login Sessions and Consents. There is no authoritative
specification for managing End-Users, and AGENTS.md places it out of scope, so
pulsar needs nothing more than a reproducible registry, which the
conformance configuration can also refer to.

## Consequences

- An End-User's Subject is a UUID written in the file, not generated, so
  that it stays the same across restarts. It is distinct from the username,
  and it is the same for every Client: pulsar offers only the public subject
  type, not pairwise.
- Startup fails on a duplicate `client_id`, Subject or username.
- Client secrets and End-User passwords appear in the file only as Argon2id
  hashes, so one hashing scheme serves both. The cost is one Argon2id
  verification per confidential Client authentication, as for a login;
  Ory Hydra likewise hashes client secrets, with PBKDF2 by default.
  `pulsar client-secret` generates a client secret of 256 random bits and
  prints it with its hash, at OWASP's minimum work factor, since the
  secret's entropy, not the work factor, guards it against guessing in
  place of the count that guards logins
  ([ADR 0005](0005-logins-throttled-per-end-user-by-delay.md)). pulsar
  cannot tell how a hash was made, so it also accepts one made elsewhere,
  and cannot check that the secret behind it is as strong
  ([survey](../research/client-secrets.md)).
- Changing a Client or End-User means editing the file and restarting.
