# Logins are throttled per End-User by a growing delay, not by lockout or address

pulsar limits online guessing of End-User passwords (RFC 6749 §10.10) by
counting the attempts to sign in, in PostgreSQL: per End-User, and per
username no End-User has. After five attempts without a success, each
further one must wait for a delay that starts at a second and doubles up
to fifteen minutes, and an attempt that comes sooner is refused, with 429,
before any hash runs. A success clears the count, and a day without an
attempt forgets it. Client secrets are protected by their entropy
instead, and are not counted. The evidence is in
[docs/research/login-throttling.md](../research/login-throttling.md).

## Considered options

- **Lockout**, as Keycloak and Zitadel offer: lets anyone who knows a
  username end that End-User's access (RFC 6819 §5.1.4.2.3). A delay
  bounds guessing to about 110 attempts a day per End-User, and signing in
  works again once the guessing stops.
- **Counting per address**, alone or paired with the End-User, as Authelia
  and Auth0 do: an attacker with many addresses guesses at one End-User's
  password without limit, and pulsar has no trusted proxy setting from
  which to take an address the client cannot forge.
- **Counting per Client** as well, so that RFC 6819 §4.3.5's "Lock
  accounts" countermeasure to guessing a Client secret applies: a
  `client_id` is public, so anyone could hold up a Client's token
  requests, and with them every login at that Client. A count that a
  success cleared would instead give an attacker five more guesses after
  each of a busy Client's own requests. §4.3.5 also lists high-entropy
  secrets (§5.1.4.2.2) and strong client authentication (§5.2.3.7); pulsar
  relies on the first, and supports `private_key_jwt` for the second.

## Consequences

- Anyone can make an End-User wait, up to fifteen minutes at a time, by
  failing to sign in as them. That is the cost of a bound that holds
  whatever addresses the attacker has; a measure per address against
  password spraying waits for a deployment that needs it.
- An attempt is counted before its password is checked, so that a burst
  of attempts at once cannot slip past the count. More than five logins
  at once as one End-User therefore wait, even if each would succeed.
- An attempt is counted only once there is room to check its password,
  so that one refused with 503 for want of room is not counted. Otherwise
  anyone could fill the room, with Client authentications, which are not
  counted, and End-Users retrying would use up their own attempts; and
  logins with made-up usernames could add counts faster than passwords
  can be checked.
- A username no End-User has is counted like one that exists, so a 429
  does not reveal which usernames exist.
- What a count is kept against is stored as an HMAC under a key derived
  from `PULSAR_SECRET`, not as typed, so that a password typed into the
  username field never reaches the database. Authelia and authentik store
  the identifier as typed.
- Each replica times the delays by its own clock, so they hold as long as
  the replicas' clocks agree, as the signing key schedule does
  ([ADR 0003](0003-signing-keys-generated-and-stored-encrypted.md)).
- A Client secret must be at least 256 bits from a cryptographically
  strong random source, as `docs/operations.md` says. RFC 6819 §5.1.4.2.2 has the
  authorization server generate it, and `pulsar client-secret` does
  (#61); pulsar sees only a secret's hash, so it cannot tell whether one
  made elsewhere meets that.
- pulsar does not claim to meet NIST SP 800-63B-4 §3.2.2, which requires
  disabling an authenticator after at most 100 consecutive failures.
- Separately, each replica runs at most as many Argon2id verifications at
  once, for logins and Client secrets together, as fill `GOMAXPROCS` times
  the memory of the largest hash in the registry, as Keycloak caps its own
  at the number of cores. A request that waits two seconds without room
  gets 503. No clause of the specifications in scope requires this; OWASP
  ASVS 5.0 15.1.3 is its evidence.
