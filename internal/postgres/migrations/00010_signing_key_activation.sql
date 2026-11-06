-- When each signing key starts signing (ADR 0003, #23). A key stored by
-- `pulsar keys rotate` signs only after a delay, so that every replica and
-- every cached JWK Set has it first; the first key, and every key stored
-- before this migration, signs from when it was generated.
--
-- When a key leaves the JWK Set is not stored: it follows from when the
-- next key starts signing (internal/signing), so a row is still never
-- updated.

-- +goose Up
ALTER TABLE signing_keys ADD COLUMN activates_at timestamptz;
UPDATE signing_keys SET activates_at = created_at;
ALTER TABLE signing_keys ALTER COLUMN activates_at SET NOT NULL;

-- +goose Down
ALTER TABLE signing_keys DROP COLUMN activates_at;
