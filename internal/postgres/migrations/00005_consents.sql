-- Consents (internal/login): what each End-User has allowed each Client to
-- receive. A row is written when an End-User first allows a Client's
-- request on the consent page, and widened each time they allow a scope
-- it did not yet hold.

-- +goose Up
CREATE TABLE consents (
    -- The End-User's Subject and the Client's client_id.
    subject text NOT NULL,
    client_id text NOT NULL,
    -- The scope values the End-User has allowed the Client, in no
    -- particular order.
    scopes text[] NOT NULL,
    PRIMARY KEY (subject, client_id)
);

-- +goose Down
DROP TABLE consents;
