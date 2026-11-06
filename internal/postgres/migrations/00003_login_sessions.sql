-- Login Sessions (internal/login), kept through scs. A row is written when
-- an End-User signs in and rewritten on each request that uses it, which
-- moves its idle expiry.

-- +goose Up
CREATE TABLE login_sessions (
    -- The SHA-256 of the session token, hex-encoded (scs's
    -- HashTokenInStore), so that no row holds a token a browser could
    -- present.
    token text PRIMARY KEY,
    -- scs's encoding of the session: its absolute deadline and its values.
    data bytea NOT NULL,
    -- When the Login Session ends, by pulsar's clock: 30 minutes after its
    -- last request or 10 hours after login, whichever comes first.
    expiry timestamptz NOT NULL
);

-- For deleting the Login Sessions that have ended.
CREATE INDEX login_sessions_expiry_idx ON login_sessions (expiry);

-- +goose Down
DROP TABLE login_sessions;
