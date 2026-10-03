package api

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/kleidion/server/internal/store"
)

// vaultMetaWire is the VaultMeta JSON shape from the Phase 3 contract
// (camelCase; binary fields base64).
type vaultMetaWire struct {
	ID            string    `json:"id"`
	Kind          string    `json:"kind"`
	EncryptedMeta string    `json:"encryptedMeta"`
	Nonce         string    `json:"nonce"`
	Role          string    `json:"role"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

func toVaultWire(v store.Vault) vaultMetaWire {
	return vaultMetaWire{
		ID:            v.ID.String(),
		Kind:          v.Kind,
		EncryptedMeta: base64.StdEncoding.EncodeToString(v.EncryptedMeta),
		Nonce:         base64.StdEncoding.EncodeToString(v.Nonce),
		Role:          v.Role,
		CreatedAt:     v.CreatedAt,
		UpdatedAt:     v.UpdatedAt,
	}
}

// vaultHandler serves the /v1/vaults endpoints.
type vaultHandler struct {
	st *store.Store
}

// registerVaultRoutes mounts the vault endpoints behind RequireSession.
func registerVaultRoutes(rg *gin.RouterGroup, st *store.Store) {
	h := &vaultHandler{st: st}
	g := rg.Group("/vaults")
	{
		g.GET("", h.list)
		g.POST("", h.create)
	}
}

// list returns every vault the caller is a member of, with their role.
func (h *vaultHandler) list(c *gin.Context) {
	userID := ctxUserID(c)
	vaults, err := h.st.ListVaultsForUser(c.Request.Context(), userID)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "failed to list vaults")
		return
	}
	out := make([]vaultMetaWire, 0, len(vaults))
	for _, v := range vaults {
		out = append(out, toVaultWire(v))
	}
	c.JSON(http.StatusOK, gin.H{"vaults": out})
}

// createVaultRequest is the POST /v1/vaults body. All secret material is
// already client-encrypted; wrappedVaultKey seals the vault key to the
// creator's X25519 public key.
type createVaultRequest struct {
	Kind            string `json:"kind"`
	EncryptedMeta   string `json:"encryptedMeta"`
	Nonce           string `json:"nonce"`
	WrappedVaultKey string `json:"wrappedVaultKey"`
}

// create makes a new vault; the caller becomes its admin.
func (h *vaultHandler) create(c *gin.Context) {
	var req createVaultRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}
	kind := req.Kind
	if kind == "" {
		kind = "personal"
	}
	if kind != "personal" && kind != "shared" {
		respondError(c, http.StatusBadRequest, "kind must be personal or shared")
		return
	}
	meta, err := decodeB64Field(req.EncryptedMeta, "encryptedMeta", false, 0)
	if err != nil {
		respondError(c, http.StatusBadRequest, err.Error())
		return
	}
	nonce, err := decodeB64Field(req.Nonce, "nonce", false, nonceLen)
	if err != nil {
		respondError(c, http.StatusBadRequest, err.Error())
		return
	}
	wrapped, err := decodeB64Field(req.WrappedVaultKey, "wrappedVaultKey", false, 0)
	if err != nil {
		respondError(c, http.StatusBadRequest, err.Error())
		return
	}

	userID := ctxUserID(c)
	v, err := h.st.CreateVault(c.Request.Context(), userID, kind, meta, nonce, wrapped)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "failed to create vault")
		return
	}
	c.JSON(http.StatusCreated, gin.H{"vault": toVaultWire(*v)})
}

// Sizes/lengths enforced by the contract.
const (
	nonceLen         = 24          // XChaCha20-Poly1305 nonce
	searchHmacLen    = 32          // HMAC-SHA256 output
	maxCiphertextLen = 1 << 20     // 1 MiB cap
)

// decodeB64Field decodes a base64 wire field. exactLen > 0 enforces an exact
// decoded length. Errors are phrased for direct use as a 400 message.
func decodeB64Field(s, name string, optional bool, exactLen int) ([]byte, error) {
	if s == "" {
		if optional {
			return nil, nil
		}
		return nil, fmt.Errorf("%s must be non-empty base64", name)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		// Tolerate URL-safe/no-padding variants clients may emit.
		if b2, err2 := base64.RawStdEncoding.DecodeString(s); err2 == nil {
			b = b2
		} else {
			return nil, fmt.Errorf("%s must be non-empty base64", name)
		}
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("%s must be non-empty base64", name)
	}
	if exactLen > 0 && len(b) != exactLen {
		return nil, fmt.Errorf("%s must decode to %d bytes", name, exactLen)
	}
	return b, nil
}

// ctxUserID pulls the authenticated user id set by RequireSession.
func ctxUserID(c *gin.Context) uuid.UUID {
	v, ok := c.Get(CtxUserID)
	if !ok {
		return uuid.Nil
	}
	id, _ := v.(uuid.UUID)
	return id
}

// ctxDeviceID pulls the session's device id set by RequireSession.
func ctxDeviceID(c *gin.Context) uuid.UUID {
	v, ok := c.Get(CtxDeviceID)
	if !ok {
		return uuid.Nil
	}
	id, _ := v.(uuid.UUID)
	return id
}

// requireMembership resolves the caller's role for a vault. Missing/invalid
// vaultId is a validation 400 per the contract. Returns ok=false after
// writing the error response.
func requireMembership(c *gin.Context, st *store.Store, vaultID uuid.UUID, mutate bool) (string, bool) {
	role, err := st.GetVaultMembership(c.Request.Context(), vaultID, ctxUserID(c))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			respondError(c, http.StatusBadRequest, "vaultId must be a vault you are a member of")
			return "", false
		}
		respondError(c, http.StatusInternalServerError, "membership check failed")
		return "", false
	}
	if mutate && role == "read" {
		respondError(c, http.StatusForbidden, "read-only vault membership")
		return "", false
	}
	return role, true
}

// parseVaultIDParam reads and validates a vaultId (query or JSON field).
func parseVaultIDParam(raw string) (uuid.UUID, error) {
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, errors.New("vaultId must be a uuid")
	}
	return id, nil
}
