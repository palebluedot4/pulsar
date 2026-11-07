-- The attempts to sign in, counted per End-User and per username no
-- End-User has (internal/guessing), so that every replica refuses an
-- attempt that comes too soon after the last (RFC 6749 §10.10;
-- docs/adr/0005-logins-throttled-per-end-user-by-delay.md). A row is
-- written by the first attempt at either, updated by each later one, and
-- deleted by a success, or by pulsar's periodic deletion a day after the
-- last attempt (cmd/pulsar).

-- +goose Up
CREATE TABLE login_attempts (
    -- What attempts are counted against, as an HMAC of its kind and name
    -- under a key derived from PULSAR_SECRET: an End-User's Subject, or a
    -- username no End-User has. A username is never stored as typed, since
    -- one may be a password typed into the wrong field.
    target bytea PRIMARY KEY,
    -- The attempts made since the last success, or since the count was
    -- forgotten.
    attempts integer NOT NULL,
    -- When the next attempt may be made, by pulsar's clock.
    next_attempt timestamptz NOT NULL,
    -- When the count is forgotten and the row may be deleted, by pulsar's
    -- clock: a day after the last attempt.
    delete_after timestamptz NOT NULL
);

-- For deleting the counts forgotten.
CREATE INDEX login_attempts_delete_after_idx ON login_attempts (delete_after);

-- +goose Down
DROP TABLE login_attempts;
