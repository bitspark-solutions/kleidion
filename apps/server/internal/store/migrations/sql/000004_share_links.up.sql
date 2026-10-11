-- 000004: encrypted share links (Phase 4, Step C).
-- Zero-knowledge: wrapped_item is the item JSON re-encrypted with a random
-- one-time link key; the link key travels ONLY in the URL fragment, never to
-- this server. The lookup token is stored as a SHA-256 hash.

CREATE TABLE share_links (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash      bytea NOT NULL UNIQUE,              -- sha256(256-bit link token)
    creator_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    item_id         uuid NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    wrapped_item    bytea NOT NULL,                     -- linkKey-encrypted item JSON
    wrapped_nonce   bytea NOT NULL,
    recipient_email text,                               -- 1:1 shares (normalized lower); NULL = anyone-with-link
    view_only       bool NOT NULL DEFAULT true,
    expires_at      timestamptz NOT NULL,
    max_views       int,                                -- NULL = unlimited
    views           int NOT NULL DEFAULT 0,
    revoked_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX share_links_creator_idx ON share_links (creator_id, created_at);
CREATE INDEX share_links_expiry_idx ON share_links (expires_at) WHERE revoked_at IS NULL;
