-- The client assertions that have authenticated a Client at the token
-- endpoint (internal/oidc), so that none authenticates twice (OpenID Connect
-- Core 1.0 §9). A row is written when an assertion is accepted. Once the
-- assertion has expired, the assertion is refused for its expiry alone, and
-- the row no longer refuses its jti: the next assertion with that jti
-- replaces it, and the next one recorded with any jti deletes it.

-- +goose Up
CREATE TABLE client_assertions (
    -- The Client the assertion authenticated, and the SHA-256 of its jti
    -- claim, so that a jti of any length fits the index. A jti is unique
    -- only among the JWTs of one issuer (RFC 7519 §4.1.7), and a client
    -- assertion's issuer is its Client.
    client_id text NOT NULL,
    jti_hash bytea NOT NULL,
    -- When the assertion expires, by pulsar's clock: its exp claim.
    expiry timestamptz NOT NULL,
    PRIMARY KEY (client_id, jti_hash)
);

-- For deleting the assertions that have expired.
CREATE INDEX client_assertions_expiry_idx ON client_assertions (expiry);

-- +goose Down
DROP TABLE client_assertions;
