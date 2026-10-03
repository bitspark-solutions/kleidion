package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Vault is a container for items. Zero-knowledge: encrypted_meta holds the
// client-encrypted vault metadata (name etc.); the server cannot read it.
type Vault struct {
	ID            uuid.UUID
	OwnerID       uuid.UUID
	Kind          string // personal | shared
	EncryptedMeta []byte
	Nonce         []byte
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DeletedAt     *time.Time

	// Role is the calling user's vault_keys role; populated only by
	// ListVaultsForUser / GetVaultMembership, empty otherwise.
	Role string
}

// CreateVault inserts a vault plus the owner's vault_keys row (role admin)
// in a single transaction. wrappedVaultKey is the vault key sealed to the
// owner's X25519 public key — opaque to the server.
func (s *Store) CreateVault(ctx context.Context, ownerID uuid.UUID, kind string, encryptedMeta, nonce, wrappedVaultKey []byte) (*Vault, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin create vault: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	const vq = `
		INSERT INTO vaults (owner_id, kind, encrypted_meta, nonce)
		VALUES ($1,$2,$3,$4)
		RETURNING id, owner_id, kind, encrypted_meta, nonce, created_at, updated_at, deleted_at`
	v := &Vault{}
	if err := tx.QueryRow(ctx, vq, ownerID, kind, encryptedMeta, nonce).
		Scan(&v.ID, &v.OwnerID, &v.Kind, &v.EncryptedMeta, &v.Nonce, &v.CreatedAt, &v.UpdatedAt, &v.DeletedAt); err != nil {
		return nil, fmt.Errorf("create vault: %w", err)
	}

	const kq = `
		INSERT INTO vault_keys (vault_id, user_id, wrapped_vault_key, role)
		VALUES ($1,$2,$3,'admin')`
	if _, err := tx.Exec(ctx, kq, v.ID, ownerID, wrappedVaultKey); err != nil {
		return nil, fmt.Errorf("create owner vault key: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit create vault: %w", err)
	}
	v.Role = "admin"
	return v, nil
}

// ListVaultsForUser returns every non-deleted vault the user holds a
// vault_keys row for, with the user's role attached.
func (s *Store) ListVaultsForUser(ctx context.Context, userID uuid.UUID) ([]Vault, error) {
	const q = `
		SELECT v.id, v.owner_id, v.kind, v.encrypted_meta, v.nonce,
		       v.created_at, v.updated_at, v.deleted_at, vk.role
		FROM vaults v
		JOIN vault_keys vk ON vk.vault_id = v.id AND vk.user_id = $1
		WHERE v.deleted_at IS NULL
		ORDER BY v.created_at`
	rows, err := s.Pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("list vaults: %w", err)
	}
	defer rows.Close()

	var out []Vault
	for rows.Next() {
		var v Vault
		if err := rows.Scan(&v.ID, &v.OwnerID, &v.Kind, &v.EncryptedMeta, &v.Nonce,
			&v.CreatedAt, &v.UpdatedAt, &v.DeletedAt, &v.Role); err != nil {
			return nil, fmt.Errorf("scan vault: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list vaults rows: %w", err)
	}
	return out, nil
}

// GetVaultMembership returns the user's role for a vault, or ErrNotFound if
// the user holds no vault_keys row (i.e. is not a member).
func (s *Store) GetVaultMembership(ctx context.Context, vaultID, userID uuid.UUID) (string, error) {
	const q = `SELECT role FROM vault_keys WHERE vault_id = $1 AND user_id = $2`
	var role string
	if err := s.Pool.QueryRow(ctx, q, vaultID, userID).Scan(&role); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("get vault membership: %w", err)
	}
	return role, nil
}

// AddVaultKey grants a user access to a vault with the given role and
// wrapped key (sharing = wrap the vault key once per member).
func (s *Store) AddVaultKey(ctx context.Context, vaultID, userID uuid.UUID, wrappedVaultKey []byte, role string) error {
	const q = `
		INSERT INTO vault_keys (vault_id, user_id, wrapped_vault_key, role)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (vault_id, user_id) DO UPDATE SET role = EXCLUDED.role`
	if _, err := s.Pool.Exec(ctx, q, vaultID, userID, wrappedVaultKey, role); err != nil {
		return fmt.Errorf("add vault key: %w", err)
	}
	return nil
}

// GetVaultMaxVersion returns the vault's current item version counter
// (COALESCE(MAX(version),0)); it is the serverVersion for delta sync.
func (s *Store) GetVaultMaxVersion(ctx context.Context, vaultID uuid.UUID) (int64, error) {
	const q = `SELECT COALESCE(MAX(version),0) FROM items WHERE vault_id = $1`
	var v int64
	if err := s.Pool.QueryRow(ctx, q, vaultID).Scan(&v); err != nil {
		return 0, fmt.Errorf("get vault max version: %w", err)
	}
	return v, nil
}

// GetSyncCursor returns the last version a device acknowledged for a vault.
// Returns ErrNotFound when the device has not posted a cursor yet.
func (s *Store) GetSyncCursor(ctx context.Context, userID, deviceID, vaultID uuid.UUID) (int64, error) {
	const q = `
		SELECT last_version FROM sync_cursors
		WHERE user_id = $1 AND device_id = $2 AND vault_id = $3`
	var v int64
	if err := s.Pool.QueryRow(ctx, q, userID, deviceID, vaultID).Scan(&v); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, fmt.Errorf("get sync cursor: %w", err)
	}
	return v, nil
}

// PostSyncCursor upserts the last version a device acknowledged for a vault.
func (s *Store) PostSyncCursor(ctx context.Context, userID, deviceID, vaultID uuid.UUID, lastVersion int64) error {
	const q = `
		INSERT INTO sync_cursors (user_id, device_id, vault_id, last_version)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (user_id, device_id, vault_id) DO UPDATE
			SET last_version = EXCLUDED.last_version, updated_at = now()`
	if _, err := s.Pool.Exec(ctx, q, userID, deviceID, vaultID, lastVersion); err != nil {
		return fmt.Errorf("post sync cursor: %w", err)
	}
	return nil
}
