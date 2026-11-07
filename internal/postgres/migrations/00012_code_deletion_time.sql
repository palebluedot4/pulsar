-- When each authorization code may be deleted, recorded on its row, and
-- the access tokens' link to their Refresh Token Family dropped
-- (internal/oidc, #53).
--
-- A code was deleted once it had expired, unless it was redeemed and its
-- access tokens might not have, or it started a Refresh Token Family that
-- had neither ended nor been revoked: each authorization request checked
-- every code so kept by a join to the families. The row now records when
-- it may be deleted, set when the code is issued and moved as its state
-- changes, and deleting compares that alone, by an index, as most
-- providers surveyed decide (docs/research/refresh-tokens.md, "Keeping and
-- deleting used codes, used refresh tokens and grants").
--
-- Revoking a family finds its access tokens by their code_hash, which
-- every one of them holds, so family_id is read by no query. Each provider
-- surveyed revokes by one identifier ("Finding every token of one
-- authorization").
--
-- The indexes are built in the migration's transaction, as in 00009:
-- authorization_codes holds codes for at most the 30 days of a family.
--
-- Unlike 00007, 00008 and 00010, this migration does not keep a replica of
-- the previous release working during a rolling deploy: such a replica
-- writes no delete_after, which is NOT NULL, and writes family_id, which
-- is gone. pulsar has not been deployed, so no such replica exists, and
-- the schema is changed in one step rather than over two releases.

-- +goose Up
-- When the code's row may be deleted, by pulsar's clock: at its expiry if
-- it is not redeemed; once redeemed, when the access token issued from it
-- expires, or, if it started a Refresh Token Family, when the family
-- ends; and once its tokens are revoked, at once. Rows written before
-- this column are kept as long as the deletion this replaces kept them,
-- which is at least as long as those rules keep them.
ALTER TABLE authorization_codes
ADD COLUMN delete_after timestamptz;

UPDATE authorization_codes c
SET delete_after = CASE
    WHEN NOT c.redeemed THEN c.expiry
    ELSE greatest(
        c.expiry + interval '10 minutes',
        (
            SELECT f.expiry
            FROM refresh_token_families f
            WHERE f.code_hash = c.code_hash
                AND NOT f.revoked
        )
    )
END;

ALTER TABLE authorization_codes
ALTER COLUMN delete_after SET NOT NULL;

-- For deleting the codes due, in place of the index on expiry, which no
-- query uses any more.
DROP INDEX authorization_codes_expiry_idx;

CREATE INDEX authorization_codes_delete_after_idx
ON authorization_codes (delete_after);

DROP INDEX access_tokens_family_id_idx;

ALTER TABLE access_tokens
DROP COLUMN family_id;

-- +goose Down
ALTER TABLE access_tokens
ADD COLUMN family_id bigint;

CREATE INDEX access_tokens_family_id_idx ON access_tokens (family_id);

DROP INDEX authorization_codes_delete_after_idx;

CREATE INDEX authorization_codes_expiry_idx ON authorization_codes (expiry);

ALTER TABLE authorization_codes
DROP COLUMN delete_after;
