-- name: ListSigningKeys :many
-- In the order they start signing, so that the key signing now is the last
-- whose activates_at has passed. A key without activates_at signs from
-- when it was generated (migration 00010).
SELECT
    kid,
    sealed_private_key,
    COALESCE(activates_at, created_at)::timestamptz AS activates_at
FROM signing_keys
ORDER BY COALESCE(activates_at, created_at), kid;

-- name: HasSigningKey :one
SELECT EXISTS (SELECT FROM signing_keys);

-- name: LockSigningKeyGeneration :exec
-- Held until the transaction ends.
SELECT pg_advisory_xact_lock(@lock_id::bigint);

-- name: InsertSigningKey :exec
INSERT INTO signing_keys (kid, sealed_private_key, created_at, activates_at)
VALUES (@kid, @sealed_private_key, @created_at, @activates_at::timestamptz);
