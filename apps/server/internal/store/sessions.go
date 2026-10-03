package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Device is a registered client device.
type Device struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	Name       string
	Platform   string
	CreatedAt  time.Time
	LastSeenAt time.Time
}

// UpsertDevice registers a device for a user. Matching is by (user, name,
// platform) so re-signing-in from the same browser reuses the device row
// instead of accumulating duplicates.
func (s *Store) UpsertDevice(ctx context.Context, userID uuid.UUID, name, platform string) (uuid.UUID, error) {
	const q = `
		INSERT INTO devices (user_id, name, platform)
		VALUES ($1,$2,$3)
		ON CONFLICT (user_id, name, platform) DO UPDATE
			SET last_seen_at = now()
		RETURNING id`
	var id uuid.UUID
	if err := s.Pool.QueryRow(ctx, q, userID, name, platform).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("upsert device: %w", err)
	}
	return id, nil
}

// Session is an authenticated session.
type Session struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	DeviceID  uuid.UUID
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// CreateSession stores a session by its token hash (never the plaintext).
func (s *Store) CreateSession(ctx context.Context, userID, deviceID uuid.UUID, tokenHash []byte, ttl time.Duration) (uuid.UUID, error) {
	const q = `
		INSERT INTO sessions (user_id, device_id, token_hash, expires_at)
		VALUES ($1,$2,$3, now() + make_interval(secs => $4))
		RETURNING id`
	var id uuid.UUID
	if err := s.Pool.QueryRow(ctx, q, userID, deviceID, tokenHash, int(ttl/time.Second)).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("create session: %w", err)
	}
	return id, nil
}

// GetSessionByTokenHash resolves a session from a token hash. Returns
// ErrNotFound if missing, expired, or revoked.
func (s *Store) GetSessionByTokenHash(ctx context.Context, tokenHash []byte) (*Session, error) {
	const q = `
		SELECT id, user_id, device_id, created_at, expires_at, revoked_at
		FROM sessions
		WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()`
	row := s.Pool.QueryRow(ctx, q, tokenHash)
	sess := &Session{}
	if err := row.Scan(&sess.ID, &sess.UserID, &sess.DeviceID, &sess.CreatedAt, &sess.ExpiresAt, &sess.RevokedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get session: %w", err)
	}
	return sess, nil
}

// RevokeSession marks a session revoked (logout).
func (s *Store) RevokeSession(ctx context.Context, id uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}
