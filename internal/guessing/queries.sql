-- Every time is pulsar's, passed in: no query reads the database's clock,
-- so that tests control it.

-- name: LockAccount :one
-- Returns the account's count, adding one already forgotten if it has
-- none, and locks its row until the transaction ends. The update changes
-- nothing; it is there because ON CONFLICT DO UPDATE, unlike a SELECT
-- after an INSERT, cannot find the row gone when a success or the periodic
-- deletion deletes it between the two.
INSERT INTO login_attempts AS a (account, attempts, next_attempt, delete_after)
VALUES (@account, 0, @now, @now)
ON CONFLICT (account) DO UPDATE SET attempts = a.attempts
RETURNING attempts, next_attempt, delete_after;

-- name: RecordAttempt :exec
UPDATE login_attempts
SET attempts = @attempts, next_attempt = @next_attempt, delete_after = @delete_after
WHERE account = @account;

-- name: ForgetAccount :exec
DELETE FROM login_attempts
WHERE account = @account;

-- name: DeleteForgottenAccounts :exec
DELETE FROM login_attempts
WHERE delete_after <= @now;
