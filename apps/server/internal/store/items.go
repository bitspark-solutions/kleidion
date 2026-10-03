package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Item is an encrypted vault entry. Zero-knowledge: ciphertext/nonce/
// search_hmac are opaque client material; the server never sees plaintext.
type Item struct {
	ID         uuid.UUID
	VaultID    uuid.UUID
	ItemType   int16 // 1=Login 2=SecureNote 3=Card 4=Identity
	Ciphertext []byte
	Nonce      []byte
	SearchHmac []byte // nil = SQL NULL
	Version    int64
	Favorite   bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
	DeletedAt  *time.Time
}

// ItemVersion is a historical (superseded) ciphertext of an item.
type ItemVersion struct {
	Version   int64
	CreatedAt time.Time
}

const itemCols = `id, vault_id, item_type, ciphertext, nonce, search_hmac,
	version, favorite, created_at, updated_at, deleted_at`

func scanItem(row pgx.Row) (*Item, error) {
	it := &Item{}
	if err := row.Scan(&it.ID, &it.VaultID, &it.ItemType, &it.Ciphertext, &it.Nonce,
		&it.SearchHmac, &it.Version, &it.Favorite, &it.CreatedAt, &it.UpdatedAt, &it.DeletedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return it, nil
}

// lockVaultRow serializes writes within a vault so the per-vault version
// counter (COALESCE(MAX(version),0)+1) stays monotonic under concurrency.
func lockVaultRow(ctx context.Context, tx pgx.Tx, vaultID uuid.UUID) error {
	var id uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM vaults WHERE id = $1 AND deleted_at IS NULL`, vaultID).Scan(&id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

func nextVaultVersion(ctx context.Context, tx pgx.Tx, vaultID uuid.UUID) (int64, error) {
	var v int64
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(MAX(version),0)+1 FROM items WHERE vault_id = $1`, vaultID).Scan(&v); err != nil {
		return 0, err
	}
	return v, nil
}

// CreateItem inserts a new item, assigning it the next per-vault version
// inside the same transaction. No item_versions row is written on create.
func (s *Store) CreateItem(ctx context.Context, vaultID uuid.UUID, itemType int16,
	ciphertext, nonce, searchHmac []byte, favorite bool) (*Item, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin create item: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	if err := lockVaultRow(ctx, tx, vaultID); err != nil {
		return nil, fmt.Errorf("create item: %w", err)
	}
	version, err := nextVaultVersion(ctx, tx, vaultID)
	if err != nil {
		return nil, fmt.Errorf("create item version: %w", err)
	}

	q := `INSERT INTO items (vault_id, item_type, ciphertext, nonce, search_hmac, version, favorite)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING ` + itemCols
	it, err := scanItem(tx.QueryRow(ctx, q, vaultID, itemType, ciphertext, nonce, searchHmac, version, favorite))
	if err != nil {
		return nil, fmt.Errorf("create item: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit create item: %w", err)
	}
	return it, nil
}

// UpdateItem replaces an item's encrypted payload, archives the PREVIOUS
// ciphertext in item_versions, and bumps the vault version — all in one
// transaction. Last-write-wins; no merge logic.
func (s *Store) UpdateItem(ctx context.Context, itemID uuid.UUID, itemType int16,
	ciphertext, nonce, searchHmac []byte, favorite bool) (*Item, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin update item: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	old, err := scanItem(tx.QueryRow(ctx,
		`SELECT `+itemCols+` FROM items WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`, itemID))
	if err != nil {
		return nil, fmt.Errorf("update item: %w", err)
	}
	if err := lockVaultRow(ctx, tx, old.VaultID); err != nil {
		return nil, fmt.Errorf("update item: %w", err)
	}
	version, err := nextVaultVersion(ctx, tx, old.VaultID)
	if err != nil {
		return nil, fmt.Errorf("update item version: %w", err)
	}

	// Archive the previous ciphertext (history), then write the new one.
	if _, err := tx.Exec(ctx,
		`INSERT INTO item_versions (item_id, version, ciphertext, nonce) VALUES ($1,$2,$3,$4)`,
		old.ID, old.Version, old.Ciphertext, old.Nonce); err != nil {
		return nil, fmt.Errorf("archive item version: %w", err)
	}

	q := `UPDATE items SET item_type = $2, ciphertext = $3, nonce = $4, search_hmac = $5,
		version = $6, favorite = $7, updated_at = now()
		WHERE id = $1 RETURNING ` + itemCols
	it, err := scanItem(tx.QueryRow(ctx, q, itemID, itemType, ciphertext, nonce, searchHmac, version, favorite))
	if err != nil {
		return nil, fmt.Errorf("update item: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit update item: %w", err)
	}
	return it, nil
}

// DeleteItem soft-deletes an item (trash tombstone) and bumps the vault
// version so clients learn about the deletion via delta sync.
func (s *Store) DeleteItem(ctx context.Context, itemID uuid.UUID) (*Item, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin delete item: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	old, err := scanItem(tx.QueryRow(ctx,
		`SELECT `+itemCols+` FROM items WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`, itemID))
	if err != nil {
		return nil, fmt.Errorf("delete item: %w", err)
	}
	if err := lockVaultRow(ctx, tx, old.VaultID); err != nil {
		return nil, fmt.Errorf("delete item: %w", err)
	}
	version, err := nextVaultVersion(ctx, tx, old.VaultID)
	if err != nil {
		return nil, fmt.Errorf("delete item version: %w", err)
	}

	q := `UPDATE items SET deleted_at = now(), version = $2, updated_at = now()
		WHERE id = $1 RETURNING ` + itemCols
	it, err := scanItem(tx.QueryRow(ctx, q, itemID, version))
	if err != nil {
		return nil, fmt.Errorf("delete item: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit delete item: %w", err)
	}
	return it, nil
}

// GetItem fetches a single item by id (including soft-deleted rows).
func (s *Store) GetItem(ctx context.Context, itemID uuid.UUID) (*Item, error) {
	it, err := scanItem(s.Pool.QueryRow(ctx, `SELECT `+itemCols+` FROM items WHERE id = $1`, itemID))
	if err != nil {
		return nil, fmt.Errorf("get item: %w", err)
	}
	return it, nil
}

// ListItemsSince returns items with version > since for a vault, INCLUDING
// soft-deleted rows (tombstones clients must apply). A non-nil searchHmac
// is ANDed as an exact match. Ordered by version ascending.
func (s *Store) ListItemsSince(ctx context.Context, vaultID uuid.UUID, since int64, searchHmac []byte) ([]Item, error) {
	q := `SELECT ` + itemCols + ` FROM items
		WHERE vault_id = $1 AND version > $2 AND ($3::bytea IS NULL OR search_hmac = $3)
		ORDER BY version`
	rows, err := s.Pool.Query(ctx, q, vaultID, since, searchHmac)
	if err != nil {
		return nil, fmt.Errorf("list items since: %w", err)
	}
	defer rows.Close()

	var out []Item
	for rows.Next() {
		var it Item
		if err := rows.Scan(&it.ID, &it.VaultID, &it.ItemType, &it.Ciphertext, &it.Nonce,
			&it.SearchHmac, &it.Version, &it.Favorite, &it.CreatedAt, &it.UpdatedAt, &it.DeletedAt); err != nil {
			return nil, fmt.Errorf("scan item: %w", err)
		}
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list items rows: %w", err)
	}
	return out, nil
}

// GetItemVersions lists the archived versions of an item (version + time
// only; historical ciphertexts stay server-side unless explicitly fetched).
func (s *Store) GetItemVersions(ctx context.Context, itemID uuid.UUID) ([]ItemVersion, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT version, created_at FROM item_versions WHERE item_id = $1 ORDER BY version`, itemID)
	if err != nil {
		return nil, fmt.Errorf("list item versions: %w", err)
	}
	defer rows.Close()

	var out []ItemVersion
	for rows.Next() {
		var v ItemVersion
		if err := rows.Scan(&v.Version, &v.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan item version: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("item versions rows: %w", err)
	}
	return out, nil
}
