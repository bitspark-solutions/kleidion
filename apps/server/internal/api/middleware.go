package api

import (
	"crypto/sha256"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/kleidion/server/internal/store"
)

// Context keys set by RequireSession. Exported so handlers and tests can
// read the resolved identity off the gin context.
const (
	// CtxUserID holds the authenticated user's id (uuid.UUID).
	CtxUserID = "kleidion.userID"
	// CtxSessionID holds the resolved session id (uuid.UUID).
	CtxSessionID = "kleidion.sessionID"
	// CtxDeviceID holds the session's device id (uuid.UUID).
	CtxDeviceID = "kleidion.deviceID"
)

// RequireSession resolves an `Authorization: Bearer <token>` header to a
// live session. The token is SHA-256-hashed and looked up via
// store.GetSessionByTokenHash (the plaintext token is never stored); expired
// or revoked sessions fail the lookup and yield a uniform 401. On success it
// sets CtxUserID, CtxSessionID, and CtxDeviceID on the gin context.
func RequireSession(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if st == nil {
			respondError(c, http.StatusUnauthorized, "not authenticated")
			c.Abort()
			return
		}
		const prefix = "Bearer "
		h := c.GetHeader("Authorization")
		if !strings.HasPrefix(h, prefix) || strings.TrimSpace(h[len(prefix):]) == "" {
			respondError(c, http.StatusUnauthorized, "not authenticated")
			c.Abort()
			return
		}
		token := strings.TrimSpace(h[len(prefix):])
		sum := sha256.Sum256([]byte(token))

		sess, err := st.GetSessionByTokenHash(c.Request.Context(), sum[:])
		if err != nil {
			// Uniform 401 for missing/expired/revoked tokens and store errors:
			// never leak which failure mode occurred.
			respondError(c, http.StatusUnauthorized, "not authenticated")
			c.Abort()
			return
		}
		c.Set(CtxUserID, sess.UserID)
		c.Set(CtxSessionID, sess.ID)
		c.Set(CtxDeviceID, sess.DeviceID)
		c.Next()
	}
}
