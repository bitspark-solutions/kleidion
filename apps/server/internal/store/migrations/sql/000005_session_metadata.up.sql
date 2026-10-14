-- 000005: session metadata for device/session management.
-- user_agent + last_used_at are REQUEST-DERIVED metadata (what the client's
-- HTTP stack sent), never vault-derived secrets — the zero-knowledge invariant
-- (ADR-001) is untouched. Device name/platform already live on `devices`.

ALTER TABLE sessions
    ADD COLUMN user_agent   text,
    ADD COLUMN last_used_at timestamptz NOT NULL DEFAULT now();
