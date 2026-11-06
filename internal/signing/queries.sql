-- name: ListSigningKeys :many
-- Oldest first, so that the newest key comes last.
SELECT kid, sealed_private_key
FROM signing_keys
ORDER BY created_at, kid;

-- name: HasSigningKey :one
SELECT EXISTS (SELECT FROM signing_keys);

-- name: LockSigningKeyGeneration :exec
-- Held until the transaction ends.
SELECT pg_advisory_xact_lock(@lock_id::bigint);

-- name: InsertSigningKey :exec
INSERT INTO signing_keys (kid, sealed_private_key, created_at)
VALUES (@kid, @sealed_private_key, @created_at);
