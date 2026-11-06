-- Authorization codes, and the access tokens issued from them
-- (internal/oidc). A code is written when the authorization endpoint issues
-- it and updated once, when the token endpoint redeems it; an access token
-- is written when it is issued. Each row is deleted once it has expired.

-- +goose Up
CREATE TABLE authorization_codes (
    -- The SHA-256 of the code, so that no row holds a code a Client could
    -- redeem.
    code_hash bytea PRIMARY KEY,
    -- The Client the code was issued to, and the redirect URI of its
    -- authorization request: a token request must present both.
    client_id text NOT NULL,
    redirect_uri text NOT NULL,
    -- The End-User's Subject.
    subject text NOT NULL,
    -- The scope values granted, in the order the Client requested them.
    scopes text[] NOT NULL,
    -- The authorization request's nonce, or '' if it had none.
    nonce text NOT NULL,
    -- When the End-User authenticated.
    auth_time timestamptz NOT NULL,
    -- When the code expires, by pulsar's clock: 60 seconds after issue.
    expiry timestamptz NOT NULL,
    -- Whether a token request has redeemed the code. A redeemed code is
    -- kept until the access tokens issued from it have expired too. A
    -- valid second redemption revokes them, found by its code_hash; it
    -- needs this row to show that its parameters are the code's (#49,
    -- migration 00009).
    redeemed boolean NOT NULL DEFAULT false
);

-- For deleting the codes that have expired.
CREATE INDEX authorization_codes_expiry_idx ON authorization_codes (expiry);

-- Each access token issued, so that UserInfo (#21) can refuse one that a
-- reused code has revoked (#22).
CREATE TABLE access_tokens (
    -- The access token's jti claim.
    jti text PRIMARY KEY,
    -- The SHA-256 of the code the token was issued from.
    code_hash bytea NOT NULL,
    -- When the token expires, by pulsar's clock: its exp claim.
    expiry timestamptz NOT NULL
);

-- For deleting the access tokens that have expired.
CREATE INDEX access_tokens_expiry_idx ON access_tokens (expiry);

-- +goose Down
DROP TABLE access_tokens;
DROP TABLE authorization_codes;
