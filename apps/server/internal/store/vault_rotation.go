package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Vault-key rotation (ADR-008): revoking a member must also make the vault's
// server-side ciphertext unreadable with the key they hold. That means
// rewriting EVERY item and the vault meta under a fresh key in one transaction
// — a partial rotation would leave rows decryptable by the revoked member.
//
// Completeness is enforced server-side, not trusted from the client: the
// submitted item set must equal the vault's rows exactly, and the submitted
// wraps must equal the remaining roster exactly.

// ErrNotAdmin means the caller lacks the admin role on the vault.
var ErrNotAdmin = errors.New("store: vault admin role required")

// Rotation set-mismatch errors. The handler turns these into 400s.
var (
	ErrWrapSet        = errors.New("store: vault key wraps must cover exactly the remaining members")
	ErrItemSet        = errors.New("store: rotation must cover every item in the vault exactly once")
	ErrSelfRevocation = errors.New("store: cannot revoke the rotating admin")
	ErrLastAdmin      = errors.New("store: cannot revoke the last admin")
)

// RotateMember is one remaining member's wrap of the NEW vault key.
type RotateMember struct {
	UserID          uuid.UUID
	WrappedVaultKey []byte
}

// RotateItem is one item re-encrypted under the NEW vault key.
type RotateItem struct {
	ItemID     uuid.UUID
	ItemType   int16
	Ciphertext []byte
	Nonce      []byte
	SearchHmac []byte
	Favorite   bool
}

// RotateVaultRequest drives POST /v1/vaults/:id/rotate-key. RevokedUserID is
// optional: rotation without a revocation is a plain key refresh.
type RotateVaultRequest struct {
	VaultID       uuid.UUID
	AdminUserID   uuid.UUID
	RevokedUserID *uuid.UUID
	EncryptedMeta []byte
	MetaNonce     []byte
	Members       []RotateMember
	Items         []RotateItem
}

// RotateVaultResult reports the post-rotation vault and its new version
// counter (clients resume delta sync from it).
type RotateVaultResult struct {
	Vault         Vault
	ServerVersion int64
}

// RotateVaultKey atomically replaces a vault's key material: the revoked
// member's access, every member's wrap, every item's ciphertext, the vault
// metadata, and the item history are all rewritten in a single transaction.
//
// Item history is PURGED (ADR-008): archived ciphertexts are still under the
// old key and no remaining member can decrypt them after rotation, so keeping
// them would only preserve a readable copy for the revoked member.
func (s *Store) RotateVaultKey(ctx context.Context, req RotateVaultRequest) (*RotateVaultResult, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin rotate vault: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	// Locking the vault row is the point; its contents are re-read after the
	// rewrite for the response.
	_, maxVersion, err := lockVaultForRotation(ctx, tx, req.VaultID)
	if err != nil {
		return nil, err
	}

	// Roles come from the existing roster only — a rotation can never grant,
	// demote, or promote.
	roles, err := lockVaultRoster(ctx, tx, req.VaultID)
	if err != nil {
		return nil, err
	}
	if _, ok := roles[req.AdminUserID]; !ok || roles[req.AdminUserID] != "admin" {
		return nil, ErrNotAdmin
	}

	remaining, err := remainingRoster(roles, req.RevokedUserID, req.AdminUserID)
	if err != nil {
		return nil, err
	}
	if err := validateWrapSet(req.Members, remaining); err != nil {
		return nil, err
	}
	itemIDs, err := lockVaultItems(ctx, tx, req.VaultID)
	if err != nil {
		return nil, err
	}
	if err := validateItemSet(req.Items, itemIDs); err != nil {
		return nil, err
	}

	// New wraps for the surviving roster, roles carried over verbatim.
	if _, err := tx.Exec(ctx, `DELETE FROM vault_keys WHERE vault_id = $1`, req.VaultID); err != nil {
		return nil, fmt.Errorf("rotate: clear vault keys: %w", err)
	}
	for _, m := range req.Members {
		const kq = `INSERT INTO vault_keys (vault_id, user_id, wrapped_vault_key, role) VALUES ($1,$2,$3,$4)`
		if _, err := tx.Exec(ctx, kq, req.VaultID, m.UserID, m.WrappedVaultKey, remaining[m.UserID]); err != nil {
			return nil, fmt.Errorf("rotate: wrap for member %s: %w", m.UserID, err)
		}
	}

	// Every item moves under the new key, each taking the next version so
	// subscribers see all of them as changes.
	version := maxVersion
	for _, it := range req.Items {
		version++
		const iq = `
			UPDATE items SET item_type = $2, ciphertext = $3, nonce = $4, search_hmac = $5,
				version = $6, favorite = $7, updated_at = now()
			WHERE id = $1 AND vault_id = $8`
		tag, err := tx.Exec(ctx, iq, it.ItemID, it.ItemType, it.Ciphertext, it.Nonce,
			it.SearchHmac, version, it.Favorite, req.VaultID)
		if err != nil {
			return nil, fmt.Errorf("rotate: re-encrypt item %s: %w", it.ItemID, err)
		}
		if tag.RowsAffected() != 1 {
			return nil, ErrItemSet
		}
	}

	if _, err := tx.Exec(ctx,
		`DELETE FROM item_versions iv USING items i WHERE iv.item_id = i.id AND i.vault_id = $1`,
		req.VaultID); err != nil {
		return nil, fmt.Errorf("rotate: purge item history: %w", err)
	}

	const uq = `
		UPDATE vaults SET encrypted_meta = $2, nonce = $3, key_epoch = key_epoch + 1, updated_at = now()
		WHERE id = $1
		RETURNING id, owner_id, kind, encrypted_meta, nonce, created_at, updated_at, deleted_at, key_epoch`
	rotated := &Vault{}
	if err := tx.QueryRow(ctx, uq, req.VaultID, req.EncryptedMeta, req.MetaNonce).
		Scan(&rotated.ID, &rotated.OwnerID, &rotated.Kind, &rotated.EncryptedMeta, &rotated.Nonce,
			&rotated.CreatedAt, &rotated.UpdatedAt, &rotated.DeletedAt, &rotated.KeyEpoch); err != nil {
		return nil, fmt.Errorf("rotate: update vault meta: %w", err)
	}
	rotated.Role = "admin"

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit rotate vault: %w", err)
	}
	return &RotateVaultResult{Vault: *rotated, ServerVersion: version}, nil
}

// lockVaultForRotation takes the vault's row lock and reads its version
// counter, so concurrent item writes cannot slip between our completeness
// check and our rewrite. Every mutating store method locks this row first,
// which is what makes MAX(version)+1 assignment safe.
func lockVaultForRotation(ctx context.Context, tx pgx.Tx, vaultID uuid.UUID) (*Vault, int64, error) {
	const q = `
		SELECT id, owner_id, kind, encrypted_meta, nonce, created_at, updated_at, deleted_at, key_epoch
		FROM vaults WHERE id = $1 AND deleted_at IS NULL
		FOR UPDATE`
	v := &Vault{}
	err := tx.QueryRow(ctx, q, vaultID).Scan(&v.ID, &v.OwnerID, &v.Kind, &v.EncryptedMeta, &v.Nonce,
		&v.CreatedAt, &v.UpdatedAt, &v.DeletedAt, &v.KeyEpoch)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, 0, ErrNotFound
		}
		return nil, 0, fmt.Errorf("rotate: lock vault: %w", err)
	}
	var maxVersion int64
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(MAX(version),0) FROM items WHERE vault_id = $1`, vaultID).Scan(&maxVersion); err != nil {
		return nil, 0, fmt.Errorf("rotate: read vault version: %w", err)
	}
	return v, maxVersion, nil
}

func lockVaultRoster(ctx context.Context, tx pgx.Tx, vaultID uuid.UUID) (map[uuid.UUID]string, error) {
	rows, err := tx.Query(ctx, `SELECT user_id, role FROM vault_keys WHERE vault_id = $1 FOR UPDATE`, vaultID)
	if err != nil {
		return nil, fmt.Errorf("rotate: lock roster: %w", err)
	}
	defer rows.Close()

	roles := make(map[uuid.UUID]string)
	for rows.Next() {
		var id uuid.UUID
		var role string
		if err := rows.Scan(&id, &role); err != nil {
			return nil, fmt.Errorf("rotate: scan roster: %w", err)
		}
		roles[id] = role
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rotate: roster rows: %w", err)
	}
	return roles, nil
}

func lockVaultItems(ctx context.Context, tx pgx.Tx, vaultID uuid.UUID) (map[uuid.UUID]bool, error) {
	rows, err := tx.Query(ctx, `SELECT id FROM items WHERE vault_id = $1 FOR UPDATE`, vaultID)
	if err != nil {
		return nil, fmt.Errorf("rotate: lock items: %w", err)
	}
	defer rows.Close()

	ids := make(map[uuid.UUID]bool)
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("rotate: scan items: %w", err)
		}
		ids[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rotate: item rows: %w", err)
	}
	return ids, nil
}

// remainingRoster drops the revoked member and refuses to leave a vault
// without an admin, or to let an admin revoke themselves.
func remainingRoster(roles map[uuid.UUID]string, revoked *uuid.UUID, caller uuid.UUID) (map[uuid.UUID]string, error) {
	out := make(map[uuid.UUID]string, len(roles))
	for id, role := range roles {
		if revoked != nil && id == *revoked {
			continue
		}
		out[id] = role
	}
	if revoked != nil {
		if _, wasMember := roles[*revoked]; !wasMember {
			return nil, ErrWrapSet // nothing to revoke: caller's roster view is stale
		}
		if *revoked == caller {
			return nil, ErrSelfRevocation
		}
		if roles[*revoked] == "admin" && !hasAdmin(out) {
			return nil, ErrLastAdmin
		}
	}
	return out, nil
}

func hasAdmin(roles map[uuid.UUID]string) bool {
	for _, r := range roles {
		if r == "admin" {
			return true
		}
	}
	return false
}

// validateWrapSet demands an exact bijection between submitted wraps and the
// remaining roster: no member without a wrap (they would be locked out) and no
// wrap for anyone outside it (that would silently (re)grant access).
func validateWrapSet(submitted []RotateMember, remaining map[uuid.UUID]string) error {
	if len(submitted) != len(remaining) {
		return ErrWrapSet
	}
	seen := make(map[uuid.UUID]bool, len(submitted))
	for _, m := range submitted {
		if len(m.WrappedVaultKey) == 0 {
			return ErrWrapSet
		}
		if _, ok := remaining[m.UserID]; !ok {
			return ErrWrapSet
		}
		if seen[m.UserID] {
			return ErrWrapSet
		}
		seen[m.UserID] = true
	}
	return nil
}

// validateItemSet demands every item row is rewritten exactly once.
func validateItemSet(submitted []RotateItem, existing map[uuid.UUID]bool) error {
	if len(submitted) != len(existing) {
		return ErrItemSet
	}
	seen := make(map[uuid.UUID]bool, len(submitted))
	for _, it := range submitted {
		if !existing[it.ItemID] || seen[it.ItemID] {
			return ErrItemSet
		}
		seen[it.ItemID] = true
	}
	return nil
}
