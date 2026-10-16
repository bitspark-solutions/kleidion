-- 000006: vault key epoch (ADR-008, rotation on member removal).
-- key_epoch increments on every vault-key rotation. Clients compare it against
-- the epoch they unlocked with; a mismatch means their cached vault key can no
-- longer decrypt the server's ciphertext, so they must re-unwrap.

ALTER TABLE vaults
    ADD COLUMN key_epoch bigint NOT NULL DEFAULT 1;
