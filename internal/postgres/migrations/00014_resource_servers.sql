-- The Resource Server each authorization code and Refresh Token Family is
-- for (internal/oidc, #75): the resource parameter of the authorization
-- request (RFC 8707 §2.1), which the access tokens issued from the code,
-- and in its family, name as their audience.
--
-- Rows written before this column are for no Resource Server, as every
-- request was. pulsar has not been deployed, so no replica of an earlier
-- release reads or writes these tables during a rolling deploy.

-- +goose Up
-- The identifier of the Resource Server, as registered and as the request
-- sent it, or '' for none: the access tokens are then for pulsar itself.
ALTER TABLE authorization_codes
ADD COLUMN resource text NOT NULL DEFAULT '';

ALTER TABLE refresh_token_families
ADD COLUMN resource text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE refresh_token_families
DROP COLUMN resource;

ALTER TABLE authorization_codes
DROP COLUMN resource;
