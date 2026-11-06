-- The PKCE code challenge of each authorization code (internal/oidc), which
-- the token endpoint verifies the code_verifier against (RFC 7636 §4.4).

-- +goose Up
-- The authorization request's code_challenge, or '' if it had none. S256
-- is the only method pulsar accepts, so the method is not stored. The
-- default stays, so that a replica not yet upgraded, which does not write
-- the column, can still issue codes during a rolling deploy; the token
-- endpoint requires a code_verifier of a public Client whatever the code's
-- challenge, so such a code gives a public Client no way around PKCE.
ALTER TABLE authorization_codes
ADD COLUMN code_challenge text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE authorization_codes
DROP COLUMN code_challenge;
