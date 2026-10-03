// Package api wires HTTP routes and middleware.
package api

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"

	"github.com/kleidion/server/internal/config"
	"github.com/kleidion/server/internal/store"
)

// NewRouter builds the Gin engine with middleware and all v1 routes.
func NewRouter(log zerolog.Logger, st *store.Store, cfg config.Config) *gin.Engine {
	r := gin.New()

	r.Use(gin.Recovery())
	r.Use(requestLogger(log))
	r.Use(securityHeaders())

	// Liveness/readiness (unauthenticated).
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	r.GET("/readyz", func(c *gin.Context) {
		if st == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "no_store"})
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		if err := st.Pool.Ping(ctx); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "db_unreachable"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})

	v1 := r.Group("/v1")
	{
		// Phase 2 will register auth routes here:
		//   POST /v1/auth/enroll/start   POST /v1/auth/enroll/finish
		//   POST /v1/auth/srp/start      POST /v1/auth/srp/finish
		//   POST /v1/auth/logout
		v1.GET("/status", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"api":     "v1",
				"version": "0.1.0",
				"auth":    "not_yet_implemented",
			})
		})
	}

	return r
}

// requestLogger emits one structured log line per request.
func requestLogger(log zerolog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		log.Info().
			Str("method", c.Request.Method).
			Str("path", c.Request.URL.Path).
			Int("status", c.Writer.Status()).
			Dur("latency", time.Since(start)).
			Str("ip", c.ClientIP()).
			Msg("request")
	}
}

// securityHeaders sets baseline hardening headers on every response.
func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Cache-Control", "no-store")
		c.Next()
	}
}
