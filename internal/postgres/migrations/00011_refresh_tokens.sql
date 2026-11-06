-- Refresh Token Families and their refresh tokens (internal/oidc). A family
-- is written when a code issued with offline access is redeemed, together
-- with its first refresh token, and the access token issued from the code
-- is recorded as the family's (#50).
--
-- The indexes are built in the migration's transaction, as in 00009: the
-- new tables are empty, and access_tokens holds at most ten minutes of
-- tokens.

-- +goose Up
CREATE TABLE refresh_token_families (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- The SHA-256 of the authorization code whose redemption started the
    -- family. A code starts at most one.
    code_hash bytea NOT NULL UNIQUE,
    -- The Client the code was issued to, which alone may use the family's
    -- refresh tokens (RFC 6749 §10.4).
    client_id text NOT NULL,
    -- The End-User's Subject.
    subject text NOT NULL,
    -- The scope values granted, offline_access among them, in the order the
    -- Client requested them.
    scopes text[] NOT NULL,
    -- The claims the authorization request's claims parameter asked for,
    -- in the form of authorization_codes.claims, and when the End-User
    -- authenticated for it: a refreshed ID token carries both.
    claims jsonb NOT NULL,
    auth_time timestamptz NOT NULL,
    -- When the family ends, by pulsar's clock: 30 days after the code was
    -- redeemed, however often it is refreshed.
    expiry timestamptz NOT NULL,
    -- Whether the family has been revoked, as a whole.
    revoked boolean NOT NULL DEFAULT false
);

-- For deleting the families that have ended.
CREATE INDEX refresh_token_families_expiry_idx
ON refresh_token_families (expiry);

-- Each refresh token issued. It expires with its family, and its row is
-- deleted with it.
CREATE TABLE refresh_tokens (
    -- The SHA-256 of the refresh token, so that no row holds one a Client
    -- could redeem.
    token_hash bytea PRIMARY KEY,
    family_id bigint NOT NULL
    REFERENCES refresh_token_families (id) ON DELETE CASCADE,
    -- Whether a token request has redeemed the refresh token, which may be
    -- redeemed once.
    used boolean NOT NULL DEFAULT false
);

-- For deleting a family's refresh tokens with it.
CREATE INDEX refresh_tokens_family_id_idx ON refresh_tokens (family_id);

-- The family an access token was issued in, if any, so that revoking the
-- family revokes it; NULL for one issued from a code without offline
-- access. It has no foreign key, as code_hash has none, so that deleting an
-- ended family need not wait for its access tokens' rows.
ALTER TABLE access_tokens
ADD COLUMN family_id bigint;

-- For finding the access tokens of a family, to revoke them.
CREATE INDEX access_tokens_family_id_idx ON access_tokens (family_id);

-- +goose Down
DROP INDEX access_tokens_family_id_idx;

ALTER TABLE access_tokens
DROP COLUMN family_id;

DROP TABLE refresh_tokens;
DROP TABLE refresh_token_families;
