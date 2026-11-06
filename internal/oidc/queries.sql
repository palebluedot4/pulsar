-- Every time is pulsar's, passed in: no query reads the database's clock,
-- so that tests control it.

-- name: InsertAuthorizationCode :exec
INSERT INTO authorization_codes (code_hash, client_id, redirect_uri, subject, scopes, nonce, auth_time, expiry)
VALUES (@code_hash, @client_id, @redirect_uri, @subject, @scopes, @nonce, @auth_time, @expiry);

-- name: RedeemAuthorizationCode :one
-- Marks the code redeemed and returns what it was issued for, if it was
-- issued to this Client for this redirect URI, has not expired and has not
-- been redeemed. Under read committed, of two transactions redeeming one
-- code, the second waits for the first and then finds it redeemed.
UPDATE authorization_codes
SET redeemed = true
WHERE code_hash = @code_hash
    AND client_id = @client_id
    AND redirect_uri = @redirect_uri
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
