-- The index by which a second redemption of an authorization code finds
-- the access tokens issued from it, to revoke them (internal/oidc, RFC 6749
-- §4.1.2). Every token request whose code cannot be redeemed looks them up,
-- so without it each would scan the table.

-- +goose Up
CREATE INDEX access_tokens_code_hash_idx ON access_tokens (code_hash);

-- +goose Down
DROP INDEX access_tokens_code_hash_idx;
