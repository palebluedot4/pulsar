-- Every time is pulsar's, passed in: no query reads the database's clock,
-- so that tests control it.

-- name: InsertAuthorizationCode :exec
INSERT INTO authorization_codes (code_hash, client_id, redirect_uri, subject, scopes, nonce, code_challenge, claims, auth_time, expiry)
VALUES (@code_hash, @client_id, @redirect_uri, @subject, @scopes, @nonce, @code_challenge, @claims, @auth_time, @expiry);

-- name: RedeemAuthorizationCode :one
-- Marks the code redeemed and returns what it was issued for, if it was
-- issued to this Client for this redirect URI, has not expired and has not
-- been redeemed. The caller checks the code challenge it returns, and
-- issues no token if the token request's code_verifier does not match it.
-- Under read committed, of two transactions redeeming one code for its
-- Client and redirect URI, the second waits for the first and then finds
-- it redeemed. One for another Client or redirect URI, or after the code
-- has expired, does not wait: the row it reads does not match, so it is
-- not locked (see LockAuthorizationCode).
UPDATE authorization_codes
SET redeemed = true
WHERE code_hash = @code_hash
    AND client_id = @client_id
    AND redirect_uri = @redirect_uri
    AND expiry > @now
    AND NOT redeemed
RETURNING subject, scopes, nonce, code_challenge, claims, auth_time;

-- name: LockAuthorizationCode :one
-- Locks the code's row, if it is still kept, until the transaction ends,
-- and returns the Client, redirect URI and code challenge it was issued
-- for, and whether it has been redeemed. Under read committed, a
-- transaction that has redeemed the code but not yet committed is waited
-- for, so that this sees the code redeemed and a later statement sees the
-- access token it records. The row is selected by its code_hash alone,
-- which never changes, so that it is locked, and so waited for, whatever
-- the transaction in progress changes.
SELECT client_id, redirect_uri, code_challenge, redeemed
FROM authorization_codes
WHERE code_hash = @code_hash
FOR UPDATE;

-- name: RevokeRefreshTokenFamilyOfCode :exec
-- Revokes the Refresh Token Family the code started, if any. It locks the
-- family's row, unless the transaction holds the lock already, so that a
-- refresh in progress in the family commits first; the caller then
-- deletes the records of the access tokens issued from the code in a later
-- statement, which sees the one that refresh recorded.
UPDATE refresh_token_families
SET revoked = true
WHERE code_hash = @code_hash;

-- name: DeleteAccessTokensOfCode :exec
-- Revokes the access tokens issued from the code, directly or in its
-- Refresh Token Family, by deleting their records.
DELETE FROM access_tokens
WHERE code_hash = @code_hash;

-- name: DeleteExpiredAuthorizationCodes :exec
-- Deletes the codes that have expired, except a redeemed one whose tokens
-- may still be revoked: it is kept until @redeemed_expiry, when its access
-- tokens have expired, and while the Refresh Token Family it started has
-- neither ended nor been revoked, so that a second redemption can still
-- show its parameters are the code's and revoke them.
--
-- TODO(#53): a code kept for its family is read and checked here on every
-- run, for up to the family's 30 days; record when each code may be
-- deleted, so that this reads only those due.
DELETE FROM authorization_codes c
WHERE c.expiry <= @now
    AND (NOT c.redeemed OR c.expiry <= @redeemed_expiry)
    AND NOT EXISTS (
        SELECT FROM refresh_token_families f
        WHERE f.code_hash = c.code_hash
            AND f.expiry > @now
            AND NOT f.revoked
    );

-- name: InsertAccessToken :exec
-- family_id is NULL for an access token issued in no Refresh Token Family.
INSERT INTO access_tokens (jti, code_hash, family_id, userinfo_claims, expiry)
VALUES (@jti, @code_hash, sqlc.narg('family_id'), @userinfo_claims, @expiry);

-- name: InsertRefreshTokenFamily :one
-- Starts the Refresh Token Family of the code whose hash is code_hash, and
-- returns its id.
INSERT INTO refresh_token_families (code_hash, client_id, subject, scopes, claims, auth_time, expiry)
VALUES (@code_hash, @client_id, @subject, @scopes, @claims, @auth_time, @expiry)
RETURNING id;

-- name: InsertRefreshToken :exec
INSERT INTO refresh_tokens (token_hash, family_id)
VALUES (@token_hash, @family_id);

-- name: LockRefreshTokenFamily :one
-- Locks the row of the refresh token's Refresh Token Family until the
-- transaction ends, and returns the family. Every transaction that redeems
-- one of the family's refresh tokens or revokes the family locks the row
-- first, so they take turns: one waits for another in progress to commit,
-- and then reads the family, and in later statements its refresh tokens
-- and access tokens, as that one left them. The lock is the one an UPDATE
-- of the row takes, which does not block recording a refresh token in the
-- family.
SELECT f.id, f.client_id, f.code_hash, f.subject, f.scopes, f.claims, f.auth_time, f.expiry, f.revoked
FROM refresh_tokens r
JOIN refresh_token_families f ON f.id = r.family_id
WHERE r.token_hash = @token_hash
FOR NO KEY UPDATE OF f;

-- name: MarkRefreshTokenUsed :execrows
-- Marks the refresh token used, and affects no row if it was already used.
UPDATE refresh_tokens
SET used = true
WHERE token_hash = @token_hash
    AND NOT used;

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

-- name: FindAccessToken :one
-- Returns the claims requested from UserInfo with the access token whose
-- jti this is, if it has not expired.
SELECT userinfo_claims
FROM access_tokens
WHERE jti = @jti
    AND expiry > @now;
