package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// corsConfig describes which origins may call the API from a browser.
type corsConfig struct {
	// allowedOrigins is the exact-match allow-list. Empty means deny all
	// cross-origin browser calls (non-browser clients like the CLI, extension
	// background scripts with host permissions, and mobile are unaffected by
	// CORS in the first place).
	allowedOrigins map[string]bool
}

// allowedHeaders are the request headers clients may send. Authorization carries
// the session token; Content-Type is needed for JSON bodies.
var allowedHeaders = "Authorization, Content-Type, X-Requested-With"

// allowedMethods are the verbs the v1 API uses. OPTIONS is required for preflight.
var allowedMethods = "GET, POST, PUT, PATCH, DELETE, OPTIONS"

// CORS returns middleware implementing Cross-Origin Resource Sharing.
//
// WHY THIS EXISTS: the web app is served from a different origin than the API
// (e.g. http://localhost:13000 -> http://localhost:18081), so browsers send a
// preflight OPTIONS request and block the call unless we answer it with the
// right Access-Control-Allow-* headers. Without this, every fetch from the UI
// fails with a CORS error and the app shows "Cannot reach the Kleidion server".
//
// Deliberately NOT using `Access-Control-Allow-Origin: *`:
//   - A wildcard cannot be combined with credentials, and
//   - an explicit allow-list is the safer default for a security product.
//
// origins is a comma-separated list of exact origins (scheme+host+port), e.g.
// "http://localhost:13000,https://app.kleidion.com". An empty string denies all
// browser cross-origin access.
func CORS(origins string) gin.HandlerFunc {
	cfg := corsConfig{allowedOrigins: map[string]bool{}}
	for _, o := range strings.Split(origins, ",") {
		o = strings.TrimRight(strings.TrimSpace(o), "/")
		if o != "" {
			cfg.allowedOrigins[o] = true
		}
	}

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")

		if origin != "" && cfg.allowedOrigins[origin] {
			h := c.Writer.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Methods", allowedMethods)
			h.Set("Access-Control-Allow-Headers", allowedHeaders)
			h.Set("Access-Control-Max-Age", "600")
			// The API is token-authenticated via the Authorization header (not
			// cookies), so credentials support is intentionally omitted; adding
			// it would widen the attack surface for no benefit.
			h.Set("Vary", "Origin")
		}

		// Answer preflight directly. Gin's router returns 404 for OPTIONS on
		// routes registered only for other methods, so preflight must be
		// short-circuited here before routing decides.
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
