package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrNotFound is returned by Get* methods when no row matches.
var ErrNotFound = errors.New("store: not found")

// User is the server-side user record. All secret material is opaque: the
// server stores an SRP verifier (never the password/Secret Key/x) and the
// client-encrypted key bundle. See ADR-005.
type User struct {
	ID                  uuid.UUID
	Email               string
	SrpSalt             []byte
	SrpVerifier         []byte
	KdfAlgo             string
	KdfParams           []byte // JSONB
	MasterPublicKey     []byte
	EncryptedPrivateKey []byte
	EncryptedSymKey     []byte
	CreatedAt           time.Time
	DisabledAt          *time.Time
}

// CreateUserRequest carries the client-supplied, already-encrypted enrollment
// material. The server validates and stores it but cannot derive anything.
type CreateUserRequest struct {
	Email               string
	SrpSalt             []byte
	SrpVerifier         []byte
	KdfAlgo             string
	KdfParams           []byte
	MasterPublicKey     []byte
	EncryptedPrivateKey []byte
	EncryptedSymKey     []byte
}

// CreateUser inserts a new user. Returns the created user or an error
// (including a unique-violation error if the email already exists).
func (s *Store) CreateUser(ctx context.Context, req CreateUserRequest) (*User, error) {
	const q = `
		INSERT INTO users (
			email, srp_salt, srp_verifier, kdf_algo, kdf_params,
			master_public_key, encrypted_private_key, encrypted_sym_key
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id, email, srp_salt, srp_verifier, kdf_algo, kdf_params,
			master_public_key, encrypted_private_key, encrypted_sym_key,
			created_at, disabled_at`
	row := s.Pool.QueryRow(ctx, q,
		req.Email, req.SrpSalt, req.SrpVerifier, req.KdfAlgo, req.KdfParams,
		req.MasterPublicKey, req.EncryptedPrivateKey, req.EncryptedSymKey)

	u := &User{}
	if err := row.Scan(&u.ID, &u.Email, &u.SrpSalt, &u.SrpVerifier, &u.KdfAlgo,
		&u.KdfParams, &u.MasterPublicKey, &u.EncryptedPrivateKey, &u.EncryptedSymKey,
		&u.CreatedAt, &u.DisabledAt); err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("email already registered: %w", err)
		}
		return nil, fmt.Errorf("create user: %w", err)
	}
	return u, nil
}

// GetUserByEmail fetches a user by email (case-insensitive via citext).
func (s *Store) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	const q = `
		SELECT id, email, srp_salt, srp_verifier, kdf_algo, kdf_params,
			master_public_key, encrypted_private_key, encrypted_sym_key,
			created_at, disabled_at
		FROM users WHERE email = $1`
	row := s.Pool.QueryRow(ctx, q, email)
	u := &User{}
	if err := row.Scan(&u.ID, &u.Email, &u.SrpSalt, &u.SrpVerifier, &u.KdfAlgo,
		&u.KdfParams, &u.MasterPublicKey, &u.EncryptedPrivateKey, &u.EncryptedSymKey,
		&u.CreatedAt, &u.DisabledAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	return u, nil
}

// GetUserByID fetches a user by id.
func (s *Store) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	const q = `
		SELECT id, email, srp_salt, srp_verifier, kdf_algo, kdf_params,
			master_public_key, encrypted_private_key, encrypted_sym_key,
			created_at, disabled_at
		FROM users WHERE id = $1`
	row := s.Pool.QueryRow(ctx, q, id)
	u := &User{}
	if err := row.Scan(&u.ID, &u.Email, &u.SrpSalt, &u.SrpVerifier, &u.KdfAlgo,
		&u.KdfParams, &u.MasterPublicKey, &u.EncryptedPrivateKey, &u.EncryptedSymKey,
		&u.CreatedAt, &u.DisabledAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	return u, nil
}

// isUniqueViolation reports a Postgres unique-constraint error (SQLSTATE 23505).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}
