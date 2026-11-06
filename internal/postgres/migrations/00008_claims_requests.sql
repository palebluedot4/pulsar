-- The claims that the claims parameter of each authorization code's request
-- asked for (internal/oidc), so that the token endpoint puts those for the
-- ID token in it, and UserInfo returns those for UserInfo (OpenID Connect
-- Core 1.0 §5.5).

-- +goose Up
-- The claims requested, as pulsar keeps them: a JSON object whose id_token
-- and userinfo members, each present only if it requests a claim, map each
-- claim pulsar can release to the values it may be released with. '{}' if
-- the request had no claims parameter, or one that requested no such claim.
-- The default stays, so that a replica not yet upgraded, which does not
-- write the column, can still issue codes during a rolling deploy; the
-- claims parameter of such a code's request is then ignored, which OpenID
-- Connect Core 1.0 §5.5.1 allows, since no error follows from a claim not
-- returned.
ALTER TABLE authorization_codes
ADD COLUMN claims jsonb NOT NULL DEFAULT '{}';

-- The claims the claims parameter requested from UserInfo, in the form of
-- the userinfo member above: '{}' if none. The default stays for the same
-- reason.
ALTER TABLE access_tokens
ADD COLUMN userinfo_claims jsonb NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE access_tokens
DROP COLUMN userinfo_claims;

ALTER TABLE authorization_codes
DROP COLUMN claims;
