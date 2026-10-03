-- 000002: SRP sign-in challenge state + user key bundle completeness.
--
-- SRP is two round-trips (start -> finish). The server must hold its secret
-- ephemeral `b` between them. Challenges are single-use, short-lived (5 min),
-- and keyed by an opaque id. Bogus challenges are also stored for unknown
-- emails so response shape/timing doesn't leak account existence.

CREATE TABLE srp_challenges (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         uuid REFERENCES users(id) ON DELETE CASCADE,  -- NULL = unknown email (bogus challenge)
    email           citext NOT NULL,
    server_secret   bytea NOT NULL,        -- b (secret ephemeral); never returned to clients
    server_public   bytea NOT NULL,        -- B (public ephemeral); returned at start
    client_public   bytea NOT NULL,        -- A (public ephemeral); supplied at start
    srp_salt        bytea NOT NULL,        -- salt the client must use for x (real or bogus)
    used_at         timestamptz,
    expires_at      timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_srp_challenges_expires ON srp_challenges(expires_at);

-- Device upsert keys on (user, name, platform): re-signing in from the same
-- browser reuses the row instead of accumulating duplicates.
CREATE UNIQUE INDEX uq_devices_user_name_platform ON devices(user_id, name, platform);

-- Device name/platform are captured at signin; index for "revoke other devices".
CREATE INDEX idx_sessions_device ON sessions(device_id);
