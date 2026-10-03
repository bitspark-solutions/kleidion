// Package config loads and validates server configuration from the environment.
package config

import (
	"fmt"
	"os"
)

// Config holds all runtime configuration for the Kleidion server.
type Config struct {
	Env  string // "development" | "production"
	Port string

	DatabaseURL string

	// SessionSecret signs/verifies session tokens. Required in production.
	SessionSecret string

	// AllowedOrigins is a comma-separated exact-match allow-list of browser
	// origins permitted to call the API (CORS). e.g.
	// "http://localhost:13000,https://app.kleidion.com".
	// Empty denies all cross-origin browser calls.
	AllowedOrigins string
}

// Load reads configuration from environment variables and validates it.
func Load() (Config, error) {
	cfg := Config{
		Env:           getEnv("KLEIDION_ENV", "development"),
		Port:          getEnv("KLEIDION_PORT", "8080"),
		DatabaseURL:   os.Getenv("KLEIDION_DATABASE_URL"),
		SessionSecret: os.Getenv("KLEIDION_SESSION_SECRET"),
		AllowedOrigins: getEnv("KLEIDION_ALLOWED_ORIGINS",
			// Dev default: the compose web service's host port. Overridden in
			// production via KLEIDION_ALLOWED_ORIGINS.
			"http://localhost:13000"),
	}

	if cfg.Env != "development" && cfg.Env != "production" {
		return cfg, fmt.Errorf("KLEIDION_ENV must be development or production, got %q", cfg.Env)
	}
	if cfg.DatabaseURL == "" {
		return cfg, fmt.Errorf("KLEIDION_DATABASE_URL is required")
	}
	if cfg.Env == "production" && len(cfg.SessionSecret) < 32 {
		return cfg, fmt.Errorf("KLEIDION_SESSION_SECRET must be at least 32 bytes in production")
	}
	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}
