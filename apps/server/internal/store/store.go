// Package store owns the Postgres connection pool and schema migrations.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"time"

	"github.com/golang-migrate/migrate/v4"
	migratepgx "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/rs/zerolog"

	"github.com/kleidion/server/internal/store/migrations"
)

// Store wraps the pgx connection pool.
type Store struct {
	Pool        *pgxpool.Pool
	databaseURL string
	log         zerolog.Logger
}

// Open creates a connection pool and verifies connectivity.
func Open(ctx context.Context, databaseURL string, log zerolog.Logger) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	cfg.MaxConns = 10
	cfg.MinConns = 1

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	// Postgres may boot after the server container; retry the ping.
	if err := pingWithRetry(ctx, pool, 10, 3*time.Second, log); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{Pool: pool, databaseURL: databaseURL, log: log}, nil
}

// Close releases the connection pool.
func (s *Store) Close() { s.Pool.Close() }

func pingWithRetry(ctx context.Context, pool *pgxpool.Pool, attempts int, delay time.Duration, log zerolog.Logger) error {
	var lastErr error
	for i := 1; i <= attempts; i++ {
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		lastErr = pool.Ping(pingCtx)
		cancel()
		if lastErr == nil {
			log.Info().Int("attempt", i).Msg("database connected")
			return nil
		}
		log.Warn().Int("attempt", i).Err(lastErr).Msg("database not ready, retrying")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	return fmt.Errorf("database unreachable after %d attempts: %w", attempts, lastErr)
}

// MigrateWithRetry applies embedded SQL migrations, retrying transient
// connection errors (e.g. Postgres restarting after a machine reboot).
func (s *Store) MigrateWithRetry(ctx context.Context, attempts int, delay time.Duration) error {
	var lastErr error
	for i := 1; i <= attempts; i++ {
		lastErr = s.migrate(ctx)
		if lastErr == nil || errors.Is(lastErr, migrate.ErrNoChange) {
			s.log.Info().Msg("migrations up to date")
			return nil
		}
		if !isTransient(lastErr) {
			return lastErr
		}
		s.log.Warn().Int("attempt", i).Err(lastErr).Msg("migration failed (transient), retrying")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	return fmt.Errorf("migrations failed after %d attempts: %w", attempts, lastErr)
}

func (s *Store) migrate(ctx context.Context) error {
	sqlFS, err := fs.Sub(migrations.FS, "sql")
	if err != nil {
		return fmt.Errorf("migration fs: %w", err)
	}
	src, err := iofs.New(sqlFS, ".")
	if err != nil {
		return fmt.Errorf("migration source: %w", err)
	}
	defer src.Close()

	// golang-migrate's pgx driver needs a *sql.DB; open a dedicated
	// connection for the migration run and close it afterwards.
	sqlDB, err := sql.Open("pgx", s.databaseURL)
	if err != nil {
		return fmt.Errorf("migration db open: %w", err)
	}
	defer sqlDB.Close()

	db, err := migratepgx.WithInstance(sqlDB, &migratepgx.Config{})
	if err != nil {
		return fmt.Errorf("migration driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", src, "postgres", db)
	if err != nil {
		return fmt.Errorf("migration init: %w", err)
	}
	if err := m.Up(); err != nil {
		return err
	}
	return nil
}

func isTransient(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	msg := err.Error()
	for _, sub := range []string{"connection refused", "server is starting", "no such host", "i/o timeout", "bad connection"} {
		if contains(msg, sub) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
