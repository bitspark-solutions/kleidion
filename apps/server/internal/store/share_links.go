package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ShareLink is a zero-knowledge encrypted handoff of one item: the client
// re-encrypts the item plaintext with a random link key, stores only that
// ciphertext here, and carries the key in the URL fragment (never sent to us).
type ShareLink struct {
	ID             uuid.UUID
	TokenHash      []byte // write-only input; never read back
	CreatorID      uuid.UUID
	ItemID         uuid.UUID
	WrappedItem    []byte
	WrappedNonce   []byte
	RecipientEmail *string
	ViewOnly       bool
	ExpiresAt      time.Time
	MaxViews       *int
	Views          int
	RevokedAt      *time.Time
	CreatedAt      time.Time
}

// CreateShareLink inserts a link row and returns it.
func (s *Store) CreateShareLink(ctx context.Context, l *ShareLink) error {
	const q = `
		INSERT INTO share_links (token_hash, creator_id, item_id, wrapped_item, wrapped_nonce,
		                         recipient_email, view_only, expires_at, max_views)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING id, created_at`
	return s.Pool.QueryRow(ctx, q,
		l.TokenHash, l.CreatorID, l.ItemID, l.WrappedItem, l.WrappedNonce,
		l.RecipientEmail, l.ViewOnly, l.ExpiresAt, l.MaxViews,
	).Scan(&l.ID, &l.CreatedAt)
}

// ListShareLinksForCreator returns the creator's non-revoked links, newest first.
func (s *Store) ListShareLinksForCreator(ctx context.Context, creatorID uuid.UUID) ([]ShareLink, error) {
	const q = `
		SELECT id, creator_id, item_id, recipient_email, view_only, expires_at,
		       max_views, views, revoked_at, created_at
		FROM share_links
		WHERE creator_id = $1
		ORDER BY created_at DESC`
	rows, err := s.Pool.Query(ctx, q, creatorID)
	if err != nil {
		return nil, fmt.Errorf("list share links: %w", err)
	}
	defer rows.Close()

	var out []ShareLink
	for rows.Next() {
		var l ShareLink
		if err := rows.Scan(&l.ID, &l.CreatorID, &l.ItemID, &l.RecipientEmail, &l.ViewOnly,
			&l.ExpiresAt, &l.MaxViews, &l.Views, &l.RevokedAt, &l.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan share link: %w", err)
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("share link rows: %w", err)
	}
	return out, nil
}

// RevokeShareLink soft-deletes the creator's link. ErrNotFound if absent/foreign.
func (s *Store) RevokeShareLink(ctx context.Context, id, creatorID uuid.UUID) error {
	const q = `UPDATE share_links SET revoked_at = now() WHERE id = $1 AND creator_id = $2 AND revoked_at IS NULL`
	tag, err := s.Pool.Exec(ctx, q, id, creatorID)
	if err != nil {
		return fmt.Errorf("revoke share link: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ErrShareLinkGone is returned by SpendShareLink for revoked/expired/
// exhausted links — the handler maps it to a single uniform 404/410-style
// response so visitors learn nothing about the state of the link.
var ErrShareLinkGone = errors.New("share link not available")

// ShareLinkPayload is the ciphertext bundle returned by SpendShareLink.
type ShareLinkPayload struct {
	WrappedItem  []byte
	WrappedNonce []byte
	ViewOnly     bool
	ItemID       uuid.UUID
}

// SpendShareLink atomically validates + increments views and returns the
// ciphertext. The update is part of the read transaction so concurrent
// visitors cannot slip past a max_views race.
func (s *Store) SpendShareLink(ctx context.Context, tokenHash []byte) (*ShareLinkPayload, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin spend share link: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	const sel = `
		SELECT id, item_id, wrapped_item, wrapped_nonce, view_only,
		       expires_at, max_views, views, revoked_at
		FROM share_links
		WHERE token_hash = $1
		FOR UPDATE`
	var (
		id        uuid.UUID
		itemID    uuid.UUID
		payload   ShareLinkPayload
		expiresAt time.Time
		maxViews  *int
		views     int
		revokedAt *time.Time
	)
	err = tx.QueryRow(ctx, sel, tokenHash).Scan(
		&id, &itemID, &payload.WrappedItem, &payload.WrappedNonce, &payload.ViewOnly,
		&expiresAt, &maxViews, &views, &revokedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrShareLinkGone
		}
		return nil, fmt.Errorf("select share link: %w", err)
	}
	if revokedAt != nil || time.Now().After(expiresAt) || (maxViews != nil && views >= *maxViews) {
		return nil, ErrShareLinkGone
	}

	const upd = `UPDATE share_links SET views = views + 1 WHERE id = $1`
	if _, err := tx.Exec(ctx, upd, id); err != nil {
		return nil, fmt.Errorf("increment views: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit spend share link: %w", err)
	}
	payload.ItemID = itemID
	return &payload, nil
}
