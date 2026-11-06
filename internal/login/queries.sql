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

-- name: FindConsent :one
SELECT scopes
FROM consents
WHERE subject = @subject AND client_id = @client_id;

-- name: GrantConsent :exec
-- Adds scopes to the Consent of the End-User for the Client, creating it if
-- there is none, in one statement, so that two grants at once both count.
INSERT INTO consents (subject, client_id, scopes)
VALUES (@subject, @client_id, @scopes::text[])
ON CONFLICT (subject, client_id) DO UPDATE
SET scopes = ARRAY(SELECT DISTINCT unnest(consents.scopes || excluded.scopes));
