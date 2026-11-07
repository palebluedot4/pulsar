-- Every time is pulsar's, passed in: no query reads the database's clock,
-- so that tests control it.

-- name: LockTarget :one
-- Returns the Target's count, adding one already forgotten if it has
-- none, and locks its row until the transaction ends. The update changes
-- nothing; it is there because ON CONFLICT DO UPDATE, unlike a SELECT
-- after an INSERT, cannot find the row gone when a success or the periodic
-- deletion deletes it between the two.
INSERT INTO login_attempts AS a (target, attempts, next_attempt, delete_after)
VALUES (@target, 0, @now, @now)
ON CONFLICT (target) DO UPDATE SET attempts = a.attempts
RETURNING attempts, next_attempt, delete_after;

-- name: RecordAttempt :exec
UPDATE login_attempts
SET attempts = @attempts, next_attempt = @next_attempt, delete_after = @delete_after
WHERE target = @target;

-- name: ForgetTarget :exec
DELETE FROM login_attempts
WHERE target = @target;

-- name: DeleteForgottenTargets :exec
DELETE FROM login_attempts
WHERE delete_after <= @now;
