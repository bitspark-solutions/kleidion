package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/kleidion/server/internal/auth"
	"github.com/kleidion/server/internal/store"
)

// ctxSessionID is the gin context key where the auth middleware stores the
// resolved session id (same value as the exported CtxSessionID).
const ctxSessionID = CtxSessionID

// authHandler holds the auth service for HTTP handlers.
type authHandler struct {
	svc *auth.Service
	log zerolog.Logger
}

// registerAuthRoutes mounts the enrollment + SRP sign-in endpoints.
// st is needed to build the RequireSession middleware for /logout.
func registerAuthRoutes(v1 *gin.RouterGroup, svc *auth.Service, st *store.Store, log zerolog.Logger) {
	h := &authHandler{svc: svc, log: log}
	a := v1.Group("/auth")
	{
		a.POST("/enroll", h.enroll)
		a.POST("/srp/start", h.srpStart)
		a.POST("/srp/finish", h.srpFinish)
		// Logout is session-authenticated: the bearer token identifies WHICH
		// session to revoke, and RequireSession makes the token unusable after
		// the revoke lands (revoked rows fail the middleware lookup).
		a.POST("/logout", RequireSession(st), h.logout)
	}
}

// enroll creates an account from client-computed, already-encrypted material.
func (h *authHandler) enroll(c *gin.Context) {
	var req auth.EnrollRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}
	resp, err := h.svc.Enroll(c.Request.Context(), &req)
	if err != nil {
		// A duplicate email is a conflict; validation problems are 400.
		if strings.Contains(err.Error(), "already registered") {
			respondError(c, http.StatusConflict, "email already registered")
			return
		}
		if isAuthValidationError(err) {
			respondError(c, http.StatusBadRequest, err.Error())
			return
		}
		h.log.Error().Err(err).Msg("enroll failed")
		respondError(c, http.StatusInternalServerError, "enrollment failed")
		return
	}
	c.JSON(http.StatusCreated, resp)
}

// srpStart is SRP step 1: returns the challenge id, salt, and B.
func (h *authHandler) srpStart(c *gin.Context) {
	var req auth.SrpStartRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}
	resp, err := h.svc.SrpStart(c.Request.Context(), &req)
	if err != nil {
		if isAuthValidationError(err) {
			respondError(c, http.StatusBadRequest, err.Error())
			return
		}
		h.log.Error().Err(err).Msg("srp start failed")
		respondError(c, http.StatusInternalServerError, "sign-in failed")
		return
	}
	c.JSON(http.StatusOK, resp)
}

// srpFinish is SRP step 2: verifies M1, issues a session, returns M2 + key bundle.
func (h *authHandler) srpFinish(c *gin.Context) {
	var req auth.SrpFinishRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}
	// Server-captured UA for the session list (client-declared fields are not
	// trusted for this).
	req.UserAgent = c.Request.UserAgent()
	resp, err := h.svc.SrpFinish(c.Request.Context(), &req)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidChallenge):
			respondError(c, http.StatusBadRequest, "challenge expired or already used")
		case errors.Is(err, auth.ErrInvalidProof):
			// Uniform 401 for wrong password AND unknown account (no enumeration).
			respondError(c, http.StatusUnauthorized, "invalid credentials")
		case errors.Is(err, auth.ErrAccountDisabled):
			respondError(c, http.StatusForbidden, "account disabled")
		case isAuthValidationError(err):
			respondError(c, http.StatusBadRequest, err.Error())
		default:
			h.log.Error().Err(err).Msg("srp finish failed")
			respondError(c, http.StatusInternalServerError, "sign-in failed")
		}
		return
	}
	c.JSON(http.StatusOK, resp)
}

// logout revokes the caller's session.
func (h *authHandler) logout(c *gin.Context) {
	// RequireSession resolved the bearer token and set the session id on the
	// context. Revoking the row makes the token fail the middleware lookup
	// immediately (revoked sessions are excluded from the token-hash query).
	sessID, err := sessionIDFromContext(c)
	if err != nil {
		// Unreachable while RequireSession is mounted; fail closed anyway.
		respondError(c, http.StatusUnauthorized, "not authenticated")
		return
	}
	if err := h.svc.Logout(c.Request.Context(), sessID); err != nil {
		h.log.Error().Err(err).Msg("logout revoke failed")
		respondError(c, http.StatusInternalServerError, "logout failed")
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// sessionIDFromContext reads the uuid session id the middleware stored.
func sessionIDFromContext(c *gin.Context) (uuid.UUID, error) {
	v, ok := c.Get(ctxSessionID)
	if !ok {
		return uuid.Nil, errors.New("no session on context")
	}
	id, ok := v.(uuid.UUID)
	if !ok || id == uuid.Nil {
		return uuid.Nil, errors.New("bad session id on context")
	}
	return id, nil
}

// respondError writes a uniform JSON error body.
func respondError(c *gin.Context, status int, msg string) {
	c.JSON(status, gin.H{"error": msg})
}

// isAuthValidationError classifies service validation errors (400-worthy).
func isAuthValidationError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, sub := range []string{
		"invalid email", "must be", "out of range", "not valid hex",
	} {
		if strings.Contains(msg, sub) {
			return true
		}
	}
	// store.ErrNotFound on a required lookup is also a client-facing 400/401.
	return errors.Is(err, store.ErrNotFound)
}
