-- 000001: core identity schema (users, devices, sessions).
-- All secret material is opaque to the server: SRP verifier/salt and
-- client-side-encrypted key bundles only. See ADR-001 and the master plan §3.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email                   citext NOT NULL UNIQUE,
    -- SRP-6a (RFC 5054, 2048-bit group, SHA-256)
    srp_salt                bytea NOT NULL,
    srp_verifier            bytea NOT NULL,
    -- KDF parameters the client must use (argon2id m/t/p or pbkdf2 rounds)
    kdf_algo                text NOT NULL DEFAULT 'argon2id',
    kdf_params              jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- Client-side key bundle (opaque ciphertext to the server)
    master_public_key       bytea NOT NULL,          -- X25519 public key
    encrypted_private_key   bytea NOT NULL,          -- wrapped with AUK
    encrypted_sym_key       bytea NOT NULL,          -- personal key set slot
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    disabled_at             timestamptz
);

CREATE TABLE devices (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        text NOT NULL,
    platform    text NOT NULL,   -- web | extension | desktop-ios | desktop-macos | desktop-windows | desktop-linux | android | cli
    trusted     boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_devices_user ON devices(user_id);

CREATE TABLE sessions (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id   uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    token_hash  bytea NOT NULL UNIQUE,   -- SHA-256 of the opaque session token
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz
);

CREATE INDEX idx_sessions_user ON sessions(user_id);
