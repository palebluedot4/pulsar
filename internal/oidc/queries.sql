-- Every time is pulsar's, passed in: no query reads the database's clock,
-- so that tests control it.

-- name: InsertAuthorizationCode :exec
INSERT INTO authorization_codes (code_hash, client_id, redirect_uri, subject, scopes, nonce, code_challenge, auth_time, expiry)
VALUES (@code_hash, @client_id, @redirect_uri, @subject, @scopes, @nonce, @code_challenge, @auth_time, @expiry);

-- name: RedeemAuthorizationCode :one
-- Marks the code redeemed and returns what it was issued for, if it was
-- issued to this Client for this redirect URI with this code challenge,
-- has not expired and has not been redeemed. The code challenge is the one
-- the token request's code_verifier makes, or '' if it sent none, so that
-- a code issued with a challenge needs its verifier, and one issued
-- without needs none and refuses one. A request that matches no row
-- leaves the code as it was. Under read committed, of two transactions
-- redeeming one code, the second waits for the first and then finds it
-- redeemed.
UPDATE authorization_codes
SET redeemed = true
WHERE code_hash = @code_hash
    AND client_id = @client_id
    AND redirect_uri = @redirect_uri
    AND code_challenge = @code_challenge
    AND expiry > @now
    AND NOT redeemed
RETURNING subject, scopes, nonce, auth_time;

-- name: DeleteExpiredAuthorizationCodes :exec
DELETE FROM authorization_codes
WHERE expiry <= @now;

-- name: InsertAccessToken :exec
INSERT INTO access_tokens (jti, code_hash, expiry)
VALUES (@jti, @code_hash, @expiry);

-- name: DeleteExpiredAccessTokens :exec
DELETE FROM access_tokens
WHERE expiry <= @now;

-- name: InsertClientAssertion :execrows
-- Records a client assertion's jti for its Client, and affects no row if
-- an assertion of that Client with that jti has not yet expired. One whose
-- row has expired but is not yet deleted is replaced. Under read
-- committed, of two transactions recording one jti at once, the second
-- waits for the first and then affects no row.
INSERT INTO client_assertions (client_id, jti_hash, expiry)
VALUES (@client_id, @jti_hash, @expiry)
ON CONFLICT (client_id, jti_hash) DO UPDATE
SET expiry = excluded.expiry
WHERE client_assertions.expiry <= @now;

-- name: DeleteExpiredClientAssertions :exec
DELETE FROM client_assertions
WHERE expiry <= @now;
