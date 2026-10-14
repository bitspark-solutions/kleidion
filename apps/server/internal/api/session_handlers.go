package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/kleidion/server/internal/auth"
)

// sessionHandler serves the Active-sessions endpoints. Mounted inside the
// RequireSession group, so every handler here can assume CtxUserID and
// CtxSessionID are set.
type sessionHandler struct {
	svc *auth.Service
	log zerolog.Logger
}

// registerSessionRoutes mounts GET /sessions + DELETE /sessions/:id.
func registerSessionRoutes(authed *gin.RouterGroup, svc *auth.Service, log zerolog.Logger) {
	h := &sessionHandler{svc: svc, log: log}
	s := authed.Group("/sessions")
	{
		s.GET("", h.list)
		s.DELETE("/:id", h.revoke)
	}
}

// list returns the caller's live sessions with device name/platform,
// User-Agent, and created/last-used metadata. Request-derived metadata only —
// never vault material (zero-knowledge invariant).
func (h *sessionHandler) list(c *gin.Context) {
	userID, sessID, err := identityFromContext(c)
	if err != nil {
		respondError(c, http.StatusUnauthorized, "not authenticated")
		return
	}
	sessions, err := h.svc.ListSessions(c.Request.Context(), userID, sessID)
	if err != nil {
		h.log.Error().Err(err).Msg("list sessions failed")
		respondError(c, http.StatusInternalServerError, "session list failed")
		return
	}
	c.JSON(http.StatusOK, gin.H{"sessions": sessions})
}

// revoke terminates a specific session owned by the caller. A session id that
// is unknown, already revoked, or belongs to someone else all answer the same
// 404 — no cross-user disclosure, no enumeration oracle.
func (h *sessionHandler) revoke(c *gin.Context) {
	userID, _, err := identityFromContext(c)
	if err != nil {
		respondError(c, http.StatusUnauthorized, "not authenticated")
		return
	}
	target, err := parseSessionIDParam(c)
	if err != nil {
		respondError(c, http.StatusBadRequest, "invalid session id")
		return
	}
	if err := h.svc.RevokeSessionForUser(c.Request.Context(), target, userID); err != nil {
		if errors.Is(err, auth.ErrSessionNotFound) {
			respondError(c, http.StatusNotFound, "session not found")
			return
		}
		h.log.Error().Err(err).Msg("revoke session failed")
		respondError(c, http.StatusInternalServerError, "session revoke failed")
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// parseSessionIDParam extracts and validates the :id path parameter.
func parseSessionIDParam(c *gin.Context) (uuid.UUID, error) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil || id == uuid.Nil {
		return uuid.Nil, errors.New("bad session id")
	}
	return id, nil
}

// identityFromContext reads (userID, sessionID) the middleware stored.
func identityFromContext(c *gin.Context) (uuid.UUID, uuid.UUID, error) {
	u, ok := c.Get(CtxUserID)
	if !ok {
		return uuid.Nil, uuid.Nil, errors.New("no user on context")
	}
	userID, ok := u.(uuid.UUID)
	if !ok || userID == uuid.Nil {
		return uuid.Nil, uuid.Nil, errors.New("bad user id on context")
	}
	sessID, err := sessionIDFromContext(c)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return userID, sessID, nil
}
