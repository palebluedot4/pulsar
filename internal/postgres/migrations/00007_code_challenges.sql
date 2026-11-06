-- The PKCE code challenge of each authorization code (internal/oidc), which
-- the token endpoint verifies the code_verifier against (RFC 7636 §4.4).

-- +goose Up
-- The authorization request's code_challenge, or '' if it had none. S256
-- is the only method pulsar accepts, so the method is not stored. The
-- default stays, so that a replica not yet upgraded, which does not write
-- the column, can still issue codes during a rolling deploy; the token
-- endpoint requires a code_verifier of a public Client whatever the code's
-- challenge, so such a code gives a public Client no way around PKCE.
--
-- The other way round is not covered: until every replica is upgraded,
-- and after this migration is rolled back, a replica that does not read
-- the column redeems a confidential Client's code without checking its
-- code_verifier. The Client still authenticates, and ADR 0002 requires
-- PKCE of public Clients only. Such a replica never redeems a public
-- Client's code, since it authenticates no public Client.
ALTER TABLE authorization_codes
ADD COLUMN code_challenge text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE authorization_codes
DROP COLUMN code_challenge;
