-- 000003: vaults, items, versioned history, and sync cursors (Phase 3).
-- Zero-knowledge: the server stores ONLY opaque ciphertext, nonces, and
-- blind search HMACs. Vault names live inside encrypted_meta. See ADR-005.

CREATE TABLE vaults (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind            text NOT NULL DEFAULT 'personal',   -- personal | shared
    encrypted_meta  bytea NOT NULL,                     -- {name,...} encrypted w/ vault key
    nonce           bytea NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz
);

CREATE TABLE vault_keys (
    vault_id        uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wrapped_vault_key bytea NOT NULL,                   -- sealed box w/ member X25519 pub
    role            text NOT NULL DEFAULT 'admin',      -- admin | write | read
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (vault_id, user_id)
);

CREATE TABLE items (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vault_id        uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    item_type       smallint NOT NULL,                  -- 1=Login 2=SecureNote 3=Card 4=Identity
    ciphertext      bytea NOT NULL,
    nonce           bytea NOT NULL,
    search_hmac     bytea,                              -- nullable; enables server-side match
    version         bigint NOT NULL DEFAULT 1,          -- monotonic per vault; drives delta sync
    favorite        boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz                         -- soft delete (trash)
);
CREATE INDEX idx_items_vault_version ON items(vault_id, version);
CREATE INDEX idx_items_search_hmac ON items(search_hmac);

CREATE TABLE item_versions (                             -- history: keep prior ciphertexts
    item_id         uuid NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    version         bigint NOT NULL,
    ciphertext      bytea NOT NULL,
    nonce           bytea NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (item_id, version)
);

CREATE TABLE sync_cursors (
    user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id       uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    vault_id        uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    last_version    bigint NOT NULL DEFAULT 0,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, device_id, vault_id)
);
