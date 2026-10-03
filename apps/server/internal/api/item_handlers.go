package api

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/kleidion/server/internal/store"
)

// itemWire is the Item JSON shape from the Phase 3 contract (camelCase;
// binary fields base64; searchHmac/deletedAt nullable).
type itemWire struct {
	ID         string     `json:"id"`
	VaultID    string     `json:"vaultId"`
	ItemType   int16      `json:"itemType"`
	Ciphertext string     `json:"ciphertext"`
	Nonce      string     `json:"nonce"`
	SearchHmac *string    `json:"searchHmac"`
	Version    int64      `json:"version"`
	Favorite   bool       `json:"favorite"`
	CreatedAt  time.Time  `json:"createdAt"`
	UpdatedAt  time.Time  `json:"updatedAt"`
	DeletedAt  *time.Time `json:"deletedAt"`
}

func toItemWire(it store.Item) itemWire {
	w := itemWire{
		ID:         it.ID.String(),
		VaultID:    it.VaultID.String(),
		ItemType:   it.ItemType,
		Ciphertext: base64.StdEncoding.EncodeToString(it.Ciphertext),
		Nonce:      base64.StdEncoding.EncodeToString(it.Nonce),
		Version:    it.Version,
		Favorite:   it.Favorite,
		CreatedAt:  it.CreatedAt,
		UpdatedAt:  it.UpdatedAt,
		DeletedAt:  it.DeletedAt,
	}
	if it.SearchHmac != nil {
		s := base64.StdEncoding.EncodeToString(it.SearchHmac)
		w.SearchHmac = &s
	}
	return w
}

func toItemsWire(items []store.Item) []itemWire {
	out := make([]itemWire, 0, len(items))
	for _, it := range items {
		out = append(out, toItemWire(it))
	}
	return out
}

// itemHandler serves the /v1/items endpoints.
type itemHandler struct {
	st *store.Store
}

// registerItemRoutes mounts the item endpoints behind RequireSession.
func registerItemRoutes(rg *gin.RouterGroup, st *store.Store) {
	h := &itemHandler{st: st}
	g := rg.Group("/items")
	{
		g.GET("", h.list)
		g.POST("", h.create)
		g.PUT("/:id", h.update)
		g.DELETE("/:id", h.delete)
		g.GET("/:id/versions", h.versions)
	}
}

// itemPayload carries the shared create/update fields for validation.
type itemPayload struct {
	ItemType   int16
	Ciphertext []byte
	Nonce      []byte
	SearchHmac []byte // nil = absent
	Favorite   bool
}

// validate decrypts nothing; it only enforces the contract's wire rules:
// itemType 1..4, non-empty base64 ciphertext <= 1 MiB, 24-byte nonce,
// 32-byte searchHmac when present.
func (p *itemPayload) validate(ciphertextB64, nonceB64, searchHmacB64 string, itemType int) error {
	if itemType < 1 || itemType > 4 {
		return errors.New("itemType must be 1..4")
	}
	p.ItemType = int16(itemType)

	ct, err := decodeB64Field(ciphertextB64, "ciphertext", false, 0)
	if err != nil {
		return err
	}
	if len(ct) > maxCiphertextLen {
		return errors.New("ciphertext exceeds 1 MiB limit")
	}
	p.Ciphertext = ct

	nonce, err := decodeB64Field(nonceB64, "nonce", false, nonceLen)
	if err != nil {
		return err
	}
	p.Nonce = nonce

	if searchHmacB64 != "" {
		hm, err := decodeB64Field(searchHmacB64, "searchHmac", false, searchHmacLen)
		if err != nil {
			return err
		}
		p.SearchHmac = hm
	} else {
		p.SearchHmac = nil
	}
	return nil
}

type createItemRequest struct {
	VaultID    string `json:"vaultId"`
	ItemType   int    `json:"itemType"`
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
	SearchHmac string `json:"searchHmac"`
	Favorite   bool   `json:"favorite"`
}

// list handles GET /v1/items?vaultId=&since=&searchHmac= — delta query
// returning items with version > since (including tombstones) plus the
// vault's current serverVersion.
func (h *itemHandler) list(c *gin.Context) {
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

	var hmac []byte
	if raw := c.Query("searchHmac"); raw != "" {
		hmac, err = decodeB64Field(raw, "searchHmac", false, searchHmacLen)
		if err != nil {
			respondError(c, http.StatusBadRequest, err.Error())
			return
		}
	}

	items, err := h.st.ListItemsSince(c.Request.Context(), vaultID, since, hmac)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "failed to list items")
		return
	}
	serverVersion, err := h.st.GetVaultMaxVersion(c.Request.Context(), vaultID)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "failed to read vault version")
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": toItemsWire(items), "serverVersion": serverVersion})
}

// create handles POST /v1/items (201). The vault version bump happens in the
// same transaction as the insert (store.CreateItem).
func (h *itemHandler) create(c *gin.Context) {
	var req createItemRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}
	vaultID, err := parseVaultIDParam(req.VaultID)
	if err != nil {
		respondError(c, http.StatusBadRequest, err.Error())
		return
	}
	if _, ok := requireMembership(c, h.st, vaultID, true); !ok {
		return
	}
	var p itemPayload
	if err := p.validate(req.Ciphertext, req.Nonce, req.SearchHmac, req.ItemType); err != nil {
		respondError(c, http.StatusBadRequest, err.Error())
		return
	}

	it, err := h.st.CreateItem(c.Request.Context(), vaultID, p.ItemType,
		p.Ciphertext, p.Nonce, p.SearchHmac, req.Favorite)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "failed to create item")
		return
	}
	c.JSON(http.StatusCreated, gin.H{"item": toItemWire(*it)})
}

type updateItemRequest struct {
	ItemType   int    `json:"itemType"`
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
	SearchHmac string `json:"searchHmac"`
	Favorite   bool   `json:"favorite"`
}

// update handles PUT /v1/items/:id — archives the previous ciphertext and
// bumps the vault version. Last-write-wins.
func (h *itemHandler) update(c *gin.Context) {
	itemID, ok := h.resolveItem(c, true)
	if !ok {
		return
	}
	var req updateItemRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}
	var p itemPayload
	if err := p.validate(req.Ciphertext, req.Nonce, req.SearchHmac, req.ItemType); err != nil {
		respondError(c, http.StatusBadRequest, err.Error())
		return
	}

	it, err := h.st.UpdateItem(c.Request.Context(), itemID, p.ItemType,
		p.Ciphertext, p.Nonce, p.SearchHmac, req.Favorite)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			respondError(c, http.StatusNotFound, "item not found")
			return
		}
		respondError(c, http.StatusInternalServerError, "failed to update item")
		return
	}
	c.JSON(http.StatusOK, gin.H{"item": toItemWire(*it)})
}

// delete handles DELETE /v1/items/:id — soft delete (tombstone) that bumps
// the vault version so other devices learn about it via delta sync.
func (h *itemHandler) delete(c *gin.Context) {
	itemID, ok := h.resolveItem(c, true)
	if !ok {
		return
	}
	it, err := h.st.DeleteItem(c.Request.Context(), itemID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			respondError(c, http.StatusNotFound, "item not found")
			return
		}
		respondError(c, http.StatusInternalServerError, "failed to delete item")
		return
	}
	c.JSON(http.StatusOK, gin.H{"item": toItemWire(*it)})
}

// versions handles GET /v1/items/:id/versions.
func (h *itemHandler) versions(c *gin.Context) {
	itemID, ok := h.resolveItem(c, false)
	if !ok {
		return
	}
	vs, err := h.st.GetItemVersions(c.Request.Context(), itemID)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "failed to list versions")
		return
	}
	out := make([]gin.H, 0, len(vs))
	for _, v := range vs {
		out = append(out, gin.H{"version": v.Version, "createdAt": v.CreatedAt})
	}
	c.JSON(http.StatusOK, gin.H{"versions": out})
}

// resolveItem parses :id, loads the item, and checks the caller's membership
// in the item's vault (mutate=true also enforces the read-role 403).
// Non-members get 404 (existence is not leaked). Writes the error response
// and returns ok=false on failure.
func (h *itemHandler) resolveItem(c *gin.Context, mutate bool) (uuid.UUID, bool) {
	itemID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		respondError(c, http.StatusBadRequest, "id must be a uuid")
		return uuid.Nil, false
	}
	it, err := h.st.GetItem(c.Request.Context(), itemID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			respondError(c, http.StatusNotFound, "item not found")
		} else {
			respondError(c, http.StatusInternalServerError, "failed to load item")
		}
		return uuid.Nil, false
	}
	role, err := h.st.GetVaultMembership(c.Request.Context(), it.VaultID, ctxUserID(c))
	if err != nil {
		// Not a member (or lookup failed): uniform 404 — do not confirm the
		// item exists to non-members.
		respondError(c, http.StatusNotFound, "item not found")
		return uuid.Nil, false
	}
	if mutate && role == "read" {
		respondError(c, http.StatusForbidden, "read-only vault membership")
		return uuid.Nil, false
	}
	return itemID, true
}

// parseSince parses the `since` delta cursor; absent means 0.
func parseSince(raw string) (int64, error) {
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return 0, errors.New("since must be a non-negative integer")
	}
	return n, nil
}
