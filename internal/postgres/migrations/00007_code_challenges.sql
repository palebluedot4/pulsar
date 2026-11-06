-- The PKCE code challenge of each authorization code (internal/oidc), which
-- the token endpoint verifies the code_verifier against (RFC 7636 §4.4).

-- +goose Up
-- The authorization request's code_challenge, or '' if it had none. S256
-- is the only method pulsar accepts, so the method is not stored. The
-- default fills the rows of codes issued before this migration, which had
-- none, and is then dropped, so that every code issued after it states
-- its challenge.
ALTER TABLE authorization_codes
ADD COLUMN code_challenge text NOT NULL DEFAULT '';

ALTER TABLE authorization_codes
ALTER COLUMN code_challenge DROP DEFAULT;

-- +goose Down
ALTER TABLE authorization_codes
DROP COLUMN code_challenge;
