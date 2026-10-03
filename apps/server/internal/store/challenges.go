package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SrpChallenge is the server-side state held between the two SRP round-trips.
// The secret ephemeral b is NEVER returned to a client.
type SrpChallenge struct {
	ID           uuid.UUID
	UserID       *uuid.UUID // nil for bogus (unknown-email) challenges
	Email        string
	ServerSecret []byte // b
	ServerPublic []byte // B
	ClientPublic []byte // A
	SrpSalt      []byte
	UsedAt       *time.Time
	ExpiresAt    time.Time
}

// CreateSrpChallenge stores a new single-use challenge.
func (s *Store) CreateSrpChallenge(ctx context.Context, userID *uuid.UUID, email string,
	serverSecret, serverPublic, clientPublic, srpSalt []byte, ttl time.Duration) (*SrpChallenge, error) {
	const q = `
		INSERT INTO srp_challenges
			(user_id, email, server_secret, server_public, client_public, srp_salt, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6, now() + make_interval(secs => $7))
		RETURNING id, user_id, email, server_secret, server_public, client_public, srp_salt, expires_at`
	ttlSeconds := int(ttl / time.Second)
	row := s.Pool.QueryRow(ctx, q, userID, email, serverSecret, serverPublic, clientPublic, srpSalt, ttlSeconds)
	c := &SrpChallenge{}
	if err := row.Scan(&c.ID, &c.UserID, &c.Email, &c.ServerSecret, &c.ServerPublic,
		&c.ClientPublic, &c.SrpSalt, &c.ExpiresAt); err != nil {
		return nil, fmt.Errorf("create srp challenge: %w", err)
	}
	return c, nil
}

// ConsumeSrpChallenge atomically fetches and marks a challenge used. Returns
// ErrNotFound if the challenge is missing, already used, or expired. The
// UPDATE ... RETURNING in a single statement makes double-spend impossible
// under concurrency (only one caller sees the row transition).
func (s *Store) ConsumeSrpChallenge(ctx context.Context, id uuid.UUID) (*SrpChallenge, error) {
	const q = `
		UPDATE srp_challenges
		SET used_at = now()
		WHERE id = $1 AND used_at IS NULL AND expires_at > now()
		RETURNING id, user_id, email, server_secret, server_public, client_public, srp_salt, expires_at`
	row := s.Pool.QueryRow(ctx, q, id)
	c := &SrpChallenge{}
	if err := row.Scan(&c.ID, &c.UserID, &c.Email, &c.ServerSecret, &c.ServerPublic,
		&c.ClientPublic, &c.SrpSalt, &c.ExpiresAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("consume srp challenge: %w", err)
	}
	return c, nil
}

// DeleteExpiredSrpChallenges garbage-collects old challenges.
func (s *Store) DeleteExpiredSrpChallenges(ctx context.Context) (int64, error) {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM srp_challenges WHERE expires_at <= now()`)
	if err != nil {
		return 0, fmt.Errorf("delete expired challenges: %w", err)
	}
	return tag.RowsAffected(), nil
}
