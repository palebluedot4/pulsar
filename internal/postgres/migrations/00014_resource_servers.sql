-- The Resource Server each authorization code and Refresh Token Family is
-- for (internal/oidc, #75): the resource parameter of the authorization
-- request (RFC 8707 §2.1), which the access tokens issued from the code,
-- and in its family, name as their audience. And the Resource Servers
-- each Consent allows (internal/login), so that a Consent to a scope
-- covers it only for the Resource Server the End-User saw it under.
--
-- Rows written before these columns are for no Resource Server, as every
-- request was. pulsar has not been deployed, so no replica of an earlier
-- release reads or writes these tables during a rolling deploy.

-- +goose Up
-- The identifier of the Resource Server, as registered and as the request
-- sent it, or '' for none: the access tokens are then for pulsar itself.
ALTER TABLE authorization_codes
ADD COLUMN resource text NOT NULL DEFAULT '';

ALTER TABLE refresh_token_families
ADD COLUMN resource text NOT NULL DEFAULT '';

-- The identifiers of the Resource Servers the End-User has allowed the
-- Client access to, in no particular order.
ALTER TABLE consents
ADD COLUMN resource_servers text[] NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE consents
DROP COLUMN resource_servers;

ALTER TABLE refresh_token_families
DROP COLUMN resource;

ALTER TABLE authorization_codes
DROP COLUMN resource;
