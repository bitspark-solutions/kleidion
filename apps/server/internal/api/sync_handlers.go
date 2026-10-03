package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/kleidion/server/internal/store"
)

// syncHandler serves the /v1/sync endpoints (delta pull + per-device cursor).
type syncHandler struct {
	st *store.Store
}

// registerSyncRoutes mounts the sync endpoints behind RequireSession.
func registerSyncRoutes(rg *gin.RouterGroup, st *store.Store) {
	h := &syncHandler{st: st}
	g := rg.Group("/sync")
	{
		g.GET("/changes", h.changes)
		g.POST("/cursor", h.postCursor)
	}
}

// changes handles GET /v1/sync/changes?vaultId=&since= — returns items with
// version > since (tombstones included), the vault's latestVersion, and
// hasMore (always false: no pagination in the Phase 3 contract).
func (h *syncHandler) changes(c *gin.Context) {
	vaultID, err := parseVaultIDParam(c.Query("vaultId"))
	if err != nil {
		respondError(c, http.StatusBadRequest, err.Error())
		return
	}
	if _, ok := requireMembership(c, h.st, vaultID, false); !ok {
		return
	}
	since, err := parseSince(c.Query("since"))
	if err != nil {
		respondError(c, http.StatusBadRequest, err.Error())
		return
	}

	items, err := h.st.ListItemsSince(c.Request.Context(), vaultID, since, nil)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "failed to fetch changes")
		return
	}
	latest, err := h.st.GetVaultMaxVersion(c.Request.Context(), vaultID)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "failed to read vault version")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"changes":       toItemsWire(items),
		"latestVersion": latest,
		"hasMore":       false,
	})
}

type postCursorRequest struct {
	VaultID     string `json:"vaultId"`
	LastVersion int64  `json:"lastVersion"`
	DeviceID    string `json:"deviceId"`
}

// postCursor handles POST /v1/sync/cursor — records the last version a
// device acknowledged for a vault.
func (h *syncHandler) postCursor(c *gin.Context) {
	var req postCursorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}
	vaultID, err := parseVaultIDParam(req.VaultID)
	if err != nil {
		respondError(c, http.StatusBadRequest, err.Error())
		return
	}
	if _, ok := requireMembership(c, h.st, vaultID, false); !ok {
		return
	}
	deviceID, err := uuid.Parse(req.DeviceID)
	if err != nil {
		respondError(c, http.StatusBadRequest, "deviceId must be a uuid")
		return
	}
	if req.LastVersion < 0 {
		respondError(c, http.StatusBadRequest, "lastVersion must be non-negative")
		return
	}

	userID := ctxUserID(c)
	ownerID, err := h.st.GetDeviceOwner(c.Request.Context(), deviceID)
	if err != nil || ownerID != userID {
		respondError(c, http.StatusBadRequest, "deviceId must be one of your devices")
		return
	}
	if err := h.st.PostSyncCursor(c.Request.Context(), userID, deviceID, vaultID, req.LastVersion); err != nil {
		respondError(c, http.StatusInternalServerError, "failed to save cursor")
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
