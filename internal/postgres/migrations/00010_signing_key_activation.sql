-- When each signing key starts signing (ADR 0003, #23). A key stored by
-- `pulsar keys rotate` signs only after a delay, so that every replica and
-- every cached JWK Set has it first.
--
-- NULL means the key signs from created_at: every key stored before this
-- migration, and any that a replica of an earlier release stores while a
-- rolling deploy runs, since such a replica does not know the column.
-- The column is therefore nullable and has no default, and no row is
-- updated.
--
-- When a key leaves the JWK Set is not stored either: it follows from when
-- the next key starts signing (internal/signing).

-- +goose Up
ALTER TABLE signing_keys ADD COLUMN activates_at timestamptz;

-- +goose Down
ALTER TABLE signing_keys DROP COLUMN activates_at;
