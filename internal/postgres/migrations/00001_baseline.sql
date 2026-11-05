-- The schema's first version, which creates nothing: each table arrives with
-- the change that needs it, in a migration of its own. goose refuses to run
-- without any migration; this one gives it a version to record, so that
-- migrating at startup, under its lock, works from the first release.

-- +goose Up
