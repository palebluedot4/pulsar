# pulsar

An OpenID Provider: it authenticates people and tells the applications they
use who they are. Terms follow OpenID Connect and OAuth 2.0; where the two
name the same thing differently, one name is chosen below.

## Parties

**OP**:
pulsar itself, the OpenID Provider that authenticates End-Users and issues
tokens about them. Called the Authorization Server only where a statement is
specific to OAuth.
_Avoid_: IdP, identity server

**End-User**:
The person who signs in at the OP.
_Avoid_: user, account, resource owner

**Client**:
An application registered with the OP that requests tokens. Called a Relying
Party only where a statement is specific to OpenID Connect.
_Avoid_: app

**machine Client**:
A Client registered for the client credentials grant alone, which requests
access tokens on its own behalf, with no End-User; its `client_id` is their
`sub`.
_Avoid_: service account, M2M client, daemon

**Resource Server**:
A server registered with the OP that accepts access tokens issued for it,
and refuses those issued for anything else.
_Avoid_: API, audience, backend, protected resource (outside RFC 9728)

## Identity

**Subject**:
The locally unique identifier the OP assigns an End-User: never reassigned,
and not the name the End-User types to sign in.
_Avoid_: user ID, username, sub (in prose)

## Authentication and authorization

**Login Session**:
The End-User's authenticated state at the OP, which spares them from signing
in again for each Client. Distinct from any session a Client keeps for
itself.
_Avoid_: session (unqualified), SSO session

**Consent**:
An End-User's recorded permission for one Client to receive a given set of
scopes, and access tokens for the Resource Servers it names.
_Avoid_: grant, approval, authorization

## Tokens

**Refresh Token Family**:
The refresh tokens descended, each replacing the last, from one
authorization code redeemed by one Client; it ends, or is revoked, as a
whole.
_Avoid_: grant, chain, lineage, token family (unqualified)
