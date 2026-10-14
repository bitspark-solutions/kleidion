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
	ID         uuid.UUID
	UserID     uuid.UUID
	DeviceID   uuid.UUID
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	UserAgent  string
	LastUsedAt time.Time
}

// SessionWithDevice joins a session with its device for the session list.
// UserAgent/LastUsedAt are request-derived metadata only (migration 000005) —
// never vault-derived secrets.
type SessionWithDevice struct {
	SessionID      uuid.UUID
	DeviceID       uuid.UUID
	DeviceName     string
	DevicePlatform string
	CreatedAt      time.Time
	LastUsedAt     time.Time
	ExpiresAt      time.Time
	UserAgent      string
}

// CreateSession stores a session by its token hash (never the plaintext).
// userAgent is the caller's User-Agent header (may be empty) and is stored as
// opaque request metadata for the Active-sessions UI.
func (s *Store) CreateSession(ctx context.Context, userID, deviceID uuid.UUID, tokenHash []byte, ttl time.Duration, userAgent string) (uuid.UUID, error) {
	const q = `
		INSERT INTO sessions (user_id, device_id, token_hash, expires_at, user_agent, last_used_at)
		VALUES ($1,$2,$3, now() + make_interval(secs => $4), NULLIF($5, ''), now())
		RETURNING id`
	var id uuid.UUID
	if err := s.Pool.QueryRow(ctx, q, userID, deviceID, tokenHash, int(ttl/time.Second), userAgent).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("create session: %w", err)
	}
	return id, nil
}

// GetSessionByTokenHash resolves a session from a token hash. Returns
// ErrNotFound if missing, expired, or revoked.
func (s *Store) GetSessionByTokenHash(ctx context.Context, tokenHash []byte) (*Session, error) {
	const q = `
		SELECT id, user_id, device_id, created_at, expires_at, revoked_at,
		       COALESCE(user_agent, ''), last_used_at
		FROM sessions
		WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()`
	row := s.Pool.QueryRow(ctx, q, tokenHash)
	sess := &Session{}
	if err := row.Scan(&sess.ID, &sess.UserID, &sess.DeviceID, &sess.CreatedAt, &sess.ExpiresAt, &sess.RevokedAt,
		&sess.UserAgent, &sess.LastUsedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get session: %w", err)
	}
	return sess, nil
}

// TouchSession bumps last_used_at for a session, throttled to once per minute
// so the auth middleware doesn't write on every request. Best-effort: callers
// ignore errors (it is metadata, not an auth decision).
func (s *Store) TouchSession(ctx context.Context, id uuid.UUID) error {
	const q = `
		UPDATE sessions SET last_used_at = now()
		WHERE id = $1 AND last_used_at < now() - interval '60 seconds'`
	if _, err := s.Pool.Exec(ctx, q, id); err != nil {
		return fmt.Errorf("touch session: %w", err)
	}
	return nil
}

// GetDeviceOwner returns the user a device belongs to (for validating that a
// sync cursor references one of the caller's own devices).
func (s *Store) GetDeviceOwner(ctx context.Context, deviceID uuid.UUID) (uuid.UUID, error) {
	var owner uuid.UUID
	if err := s.Pool.QueryRow(ctx, `SELECT user_id FROM devices WHERE id = $1`, deviceID).Scan(&owner); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrNotFound
		}
		return uuid.Nil, fmt.Errorf("get device owner: %w", err)
	}
	return owner, nil
}

// ListActiveSessions returns live (unrevoked, unexpired) sessions for a user,
// newest first, joined with device name/platform. currentSessionID is echoed
// back in the row's IsCurrent marking via the caller comparing ids.
func (s *Store) ListActiveSessions(ctx context.Context, userID uuid.UUID) ([]SessionWithDevice, error) {
	const q = `
		SELECT se.id, se.device_id, d.name, d.platform,
		       se.created_at, se.last_used_at, se.expires_at, COALESCE(se.user_agent, '')
		FROM sessions se
		JOIN devices d ON d.id = se.device_id
		WHERE se.user_id = $1 AND se.revoked_at IS NULL AND se.expires_at > now()
		ORDER BY se.created_at DESC`
	rows, err := s.Pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()
	var out []SessionWithDevice
	for rows.Next() {
		var r SessionWithDevice
		if err := rows.Scan(&r.SessionID, &r.DeviceID, &r.DeviceName, &r.DevicePlatform,
			&r.CreatedAt, &r.LastUsedAt, &r.ExpiresAt, &r.UserAgent); err != nil {
			return nil, fmt.Errorf("list sessions scan: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list sessions rows: %w", err)
	}
	return out, nil
}

// RevokeSession marks a session revoked (logout).
func (s *Store) RevokeSession(ctx context.Context, id uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// RevokeSessionForUser revokes a session ONLY if it belongs to userID.
// Returns false (with no error) when the session does not exist, is already
// revoked, or belongs to another user — the handler answers a uniform 404,
// so this never discloses other users' session ids.
func (s *Store) RevokeSessionForUser(ctx context.Context, sessionID, userID uuid.UUID) (bool, error) {
	const q = `
		UPDATE sessions SET revoked_at = now()
		WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
		RETURNING id`
	var got uuid.UUID
	err := s.Pool.QueryRow(ctx, q, sessionID, userID).Scan(&got)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("revoke session for user: %w", err)
	}
	return true, nil
}
