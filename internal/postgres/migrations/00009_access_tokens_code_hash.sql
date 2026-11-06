-- The index by which a second redemption of an authorization code finds
-- the access tokens issued from it, to revoke them (internal/oidc, RFC 6749
-- §4.1.2). Every valid second redemption of a code looks them up, so
-- without it each would scan the table.
--
-- The index is built in the migration's transaction, not CONCURRENTLY,
-- which blocks recording access tokens while it builds. The table holds
-- only access tokens not yet expired, at most ten minutes of them, so the
-- build is brief; a concurrent build that failed would leave an invalid
-- index behind for the next run to trip over.

-- +goose Up
CREATE INDEX access_tokens_code_hash_idx ON access_tokens (code_hash);

-- +goose Down
DROP INDEX access_tokens_code_hash_idx;
