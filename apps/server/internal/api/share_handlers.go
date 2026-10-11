package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/kleidion/server/internal/store"
)

// shareHandler serves the Phase 4 share-link endpoints. Zero-knowledge: the
// server stores only ciphertext re-encrypted with a client-generated link key;
// the link key travels in the URL fragment and the raw token is never stored
// (SHA-256 hash only).
type shareHandler struct {
	st *store.Store
}

type shareLinkWire struct {
	ID             string     `json:"id"`
	ItemID         string     `json:"itemId"`
	RecipientEmail *string    `json:"recipientEmail"`
	ViewOnly       bool       `json:"viewOnly"`
	ExpiresAt      time.Time  `json:"expiresAt"`
	MaxViews       *int       `json:"maxViews"`
	Views          int        `json:"views"`
	RevokedAt      *time.Time `json:"revokedAt"`
	CreatedAt      time.Time  `json:"createdAt"`
}

func toShareLinkWire(l store.ShareLink) shareLinkWire {
	return shareLinkWire{
		ID:             l.ID.String(),
		ItemID:         l.ItemID.String(),
		RecipientEmail: l.RecipientEmail,
		ViewOnly:       l.ViewOnly,
		ExpiresAt:      l.ExpiresAt,
		MaxViews:       l.MaxViews,
		Views:          l.Views,
		RevokedAt:      l.RevokedAt,
		CreatedAt:      l.CreatedAt,
	}
}

// registerShareRoutes mounts the authed creator endpoints.
func registerShareRoutes(rg *gin.RouterGroup, st *store.Store) {
	h := &shareHandler{st: st}
	g := rg.Group("/share-links")
	{
		g.POST("", h.create)
		g.GET("", h.list)
		g.DELETE("/:id", h.revoke)
	}
}

// registerPublicShareRoutes mounts the UNAUTHENTICATED visitor endpoint on the
// v1 group (outside RequireSession).
func registerPublicShareRoutes(v1 *gin.RouterGroup, st *store.Store) {
	h := &shareHandler{st: st}
	v1.POST("/public/share-links/:token", h.redeem)
}

type createShareLinkRequest struct {
	ItemID         string `json:"itemId"`
	WrappedItem    string `json:"wrappedItem"`
	WrappedNonce   string `json:"wrappedNonce"`
	RecipientEmail string `json:"recipientEmail"`
	ViewOnly       *bool  `json:"viewOnly"`
	ExpiresAt      string `json:"expiresAt"` // RFC3339
	MaxViews       *int   `json:"maxViews"`
}

// create stores a new link and returns the raw token exactly once.
func (h *shareHandler) create(c *gin.Context) {
	var req createShareLinkRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}
	itemID, err := uuid.Parse(req.ItemID)
	if err != nil {
		respondError(c, http.StatusBadRequest, "itemId must be a uuid")
		return
	}
	wrapped, err := decodeB64Field(req.WrappedItem, "wrappedItem", false, 0)
	if err != nil {
		respondError(c, http.StatusBadRequest, err.Error())
		return
	}
	if len(wrapped) > maxCiphertextLen {
		respondError(c, http.StatusBadRequest, "wrappedItem too large")
		return
	}
	nonce, err := decodeB64Field(req.WrappedNonce, "wrappedNonce", false, nonceLen)
	if err != nil {
		respondError(c, http.StatusBadRequest, err.Error())
		return
	}
	expiresAt, err := time.Parse(time.RFC3339, req.ExpiresAt)
	if err != nil {
		respondError(c, http.StatusBadRequest, "expiresAt must be RFC3339")
		return
	}
	if expiresAt.Before(time.Now().UTC()) {
		respondError(c, http.StatusBadRequest, "expiresAt must be in the future")
		return
	}
	if req.MaxViews != nil && *req.MaxViews < 1 {
		respondError(c, http.StatusBadRequest, "maxViews must be >= 1")
		return
	}

	// The creator must be a member of the item's vault.
	item, err := h.st.GetItem(c.Request.Context(), itemID)
	if err != nil || item == nil {
		respondError(c, http.StatusBadRequest, "itemId must be an item you can access")
		return
	}
	if _, ok := requireMembership(c, h.st, item.VaultID, false); !ok {
		return
	}

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		respondError(c, http.StatusInternalServerError, "failed to generate token")
		return
	}
	sum := sha256.Sum256(token)

	viewOnly := true
	if req.ViewOnly != nil {
		viewOnly = *req.ViewOnly
	}
	var email *string
	if req.RecipientEmail != "" {
		e := normalizeEmail(req.RecipientEmail)
		email = &e
	}
	l := &store.ShareLink{
		TokenHash:      sum[:],
		CreatorID:      ctxUserID(c),
		ItemID:         itemID,
		WrappedItem:    wrapped,
		WrappedNonce:   nonce,
		RecipientEmail: email,
		ViewOnly:       viewOnly,
		ExpiresAt:      expiresAt,
		MaxViews:       req.MaxViews,
	}
	if err := h.st.CreateShareLink(c.Request.Context(), l); err != nil {
		respondError(c, http.StatusInternalServerError, "failed to create share link")
		return
	}
	// The raw token is shown ONCE; only its hash lives in the DB.
	c.JSON(http.StatusCreated, gin.H{
		"shareLink": toShareLinkWire(*l),
		"token":     base64.RawURLEncoding.EncodeToString(token),
	})
}

// list returns the creator's links (never the tokens).
func (h *shareHandler) list(c *gin.Context) {
	links, err := h.st.ListShareLinksForCreator(c.Request.Context(), ctxUserID(c))
	if err != nil {
		respondError(c, http.StatusInternalServerError, "failed to list share links")
		return
	}
	out := make([]shareLinkWire, 0, len(links))
	for _, l := range links {
		out = append(out, toShareLinkWire(l))
	}
	c.JSON(http.StatusOK, gin.H{"shareLinks": out})
}

// revoke soft-deletes one of the creator's links.
func (h *shareHandler) revoke(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		respondError(c, http.StatusBadRequest, "id must be a uuid")
		return
	}
	if err := h.st.RevokeShareLink(c.Request.Context(), id, ctxUserID(c)); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			respondError(c, http.StatusNotFound, "share link not found")
			return
		}
		respondError(c, http.StatusInternalServerError, "failed to revoke share link")
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// redeem handles the unauthenticated visitor POST. Uniform failure for
// unknown/expired/exhausted/revoked so the endpoint leaks nothing.
func (h *shareHandler) redeem(c *gin.Context) {
	raw, err := base64.RawURLEncoding.DecodeString(c.Param("token"))
	if err != nil || len(raw) != 32 {
		respondError(c, http.StatusNotFound, "share link not found")
		return
	}
	sum := sha256.Sum256(raw)
	payload, err := h.st.SpendShareLink(c.Request.Context(), sum[:])
	if err != nil {
		if errors.Is(err, store.ErrShareLinkGone) {
			respondError(c, http.StatusNotFound, "share link not found")
			return
		}
		respondError(c, http.StatusInternalServerError, "failed to fetch share")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"wrappedItem":  base64.StdEncoding.EncodeToString(payload.WrappedItem),
		"wrappedNonce": base64.StdEncoding.EncodeToString(payload.WrappedNonce),
		"viewOnly":     payload.ViewOnly,
	})
}

// normalizeEmail lowercases/trims an email for storage and comparison.
func normalizeEmail(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
