-- Every time is pulsar's, passed in: no query reads the database's clock,
-- so that tests control it.

-- name: FindLoginSession :one
SELECT data
FROM login_sessions
WHERE token = @token AND expiry > @now;

-- name: CommitLoginSession :exec
INSERT INTO login_sessions (token, data, expiry)
VALUES (@token, @data, @expiry)
ON CONFLICT (token) DO UPDATE SET data = excluded.data, expiry = excluded.expiry;

-- name: DeleteLoginSession :exec
DELETE FROM login_sessions
WHERE token = @token;

-- name: DeleteEndedLoginSessions :exec
DELETE FROM login_sessions
WHERE expiry <= @now;
