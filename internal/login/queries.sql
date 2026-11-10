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
SELECT scopes, resource_servers
FROM consents
WHERE subject = @subject AND client_id = @client_id;

-- name: AddToConsent :exec
-- Adds scopes and Resource Servers to the Consent of the End-User for the
-- Client, creating it if there is none, in one statement, so that two
-- additions at once both count.
INSERT INTO consents (subject, client_id, scopes, resource_servers)
VALUES (@subject, @client_id, @scopes, @resource_servers)
ON CONFLICT (subject, client_id) DO UPDATE
SET scopes = ARRAY(SELECT DISTINCT unnest(consents.scopes || excluded.scopes)),
    resource_servers = ARRAY(SELECT DISTINCT unnest(consents.resource_servers || excluded.resource_servers));
