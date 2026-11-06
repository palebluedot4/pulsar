-- Signing keys (ADR 0003). A row is never updated: a key is added, and
-- later rotation (#23) adds more, with columns of its own for when a key
-- starts signing and when it leaves the JWK Set.

-- +goose Up
CREATE TABLE signing_keys (
    -- The key's RFC 7638 JWK Thumbprint, SHA-256, base64url-encoded.
    kid text PRIMARY KEY,
    -- The private key in PKCS #8 DER, sealed with AES-256-GCM under a key
    -- derived from PULSAR_SECRET, with kid as additional data. The
    -- public key is derived from it, so no row holds a key in the clear.
    sealed_private_key bytea NOT NULL,
    -- When the key was generated, by pulsar's clock.
    created_at timestamptz NOT NULL
);

-- +goose Down
DROP TABLE signing_keys;
