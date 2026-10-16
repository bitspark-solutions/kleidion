package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/kleidion/server/internal/store"
)

// maxRotationItems caps one rotation request's item payload. Rotation is
// all-or-nothing (a partial rotation defeats the purpose), so this is a memory
// guard rather than a paging mechanism.
const maxRotationItems = 5000

// rotateHandler serves POST /v1/vaults/:id/rotate-key (ADR-008).
//
// Zero-knowledge: the server is handed opaque ciphertext produced on the
// admin's device; it can neither read it nor rotate a key by itself. Its job is
// to make the swap atomic and to REFUSE a partial submission, because a
// rotation that misses one item leaves that item decryptable with the key the
// revoked member still holds.
type rotateHandler struct {
	st *store.Store
}

func registerRotationRoutes(rg *gin.RouterGroup, st *store.Store) {
	h := &rotateHandler{st: st}
	rg.POST("/vaults/:id/rotate-key", h.rotate)
}

type rotateMemberWire struct {
	UserID          string `json:"userId"`
	WrappedVaultKey string `json:"wrappedVaultKey"`
}

type rotateItemWire struct {
	ID         string `json:"id"`
	ItemType   int    `json:"itemType"`
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
	SearchHmac string `json:"searchHmac"`
	Favorite   bool   `json:"favorite"`
}

type rotateKeyRequest struct {
	// RevokedUserID is optional: omit it for a plain key refresh.
	RevokedUserID string             `json:"revokedUserId"`
	EncryptedMeta string             `json:"encryptedMeta"`
	Nonce         string             `json:"nonce"`
	Members       []rotateMemberWire `json:"members"`
	Items         []rotateItemWire   `json:"items"`
}

func (h *rotateHandler) rotate(c *gin.Context) {
	vaultID, ok := parseVaultParam(c)
	if !ok {
		return
	}
	// Cheap pre-check for a clean 403; the admin role is re-verified inside the
	// rotation transaction against the locked roster.
	if !requireAdmin(c, h.st, vaultID) {
		return
	}
	var req rotateKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}

	meta, err := decodeB64Field(req.EncryptedMeta, "encryptedMeta", false, 0)
	if err != nil {
		respondError(c, http.StatusBadRequest, err.Error())
		return
	}
	metaNonce, err := decodeB64Field(req.Nonce, "nonce", false, nonceLen)
	if err != nil {
		respondError(c, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Items) == 0 {
		respondError(c, http.StatusBadRequest, "items must cover every item in the vault")
		return
	}
	if len(req.Items) > maxRotationItems {
		respondError(c, http.StatusRequestEntityTooLarge, "vault is too large to rotate in one request")
		return
	}

	members, err := parseRotateMembers(req.Members)
	if err != nil {
		respondError(c, http.StatusBadRequest, err.Error())
		return
	}
	items, err := parseRotateItems(req.Items)
	if err != nil {
		respondError(c, http.StatusBadRequest, err.Error())
		return
	}

	var revoked *uuid.UUID
	if req.RevokedUserID != "" {
		id, err := uuid.Parse(req.RevokedUserID)
		if err != nil {
			respondError(c, http.StatusBadRequest, "revokedUserId must be a uuid")
			return
		}
		revoked = &id
	}

	res, err := h.st.RotateVaultKey(c.Request.Context(), store.RotateVaultRequest{
		VaultID:       vaultID,
		AdminUserID:   ctxUserID(c),
		RevokedUserID: revoked,
		EncryptedMeta: meta,
		MetaNonce:     metaNonce,
		Members:       members,
		Items:         items,
	})
	if err != nil {
		respondRotationError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"vault":         toVaultWire(res.Vault),
		"serverVersion": res.ServerVersion,
		"keyEpoch":      res.Vault.KeyEpoch,
	})
}

func parseRotateMembers(in []rotateMemberWire) ([]store.RotateMember, error) {
	if len(in) == 0 {
		return nil, errors.New("members must cover every remaining member")
	}
	out := make([]store.RotateMember, 0, len(in))
	for i, m := range in {
		userID, err := uuid.Parse(m.UserID)
		if err != nil {
			return nil, errors.New(field("members", i, "userId") + " must be a uuid")
		}
		wrapped, err := decodeB64Field(m.WrappedVaultKey, field("members", i, "wrappedVaultKey"), false, 0)
		if err != nil {
			return nil, err
		}
		out = append(out, store.RotateMember{UserID: userID, WrappedVaultKey: wrapped})
	}
	return out, nil
}

func parseRotateItems(in []rotateItemWire) ([]store.RotateItem, error) {
	out := make([]store.RotateItem, 0, len(in))
	for i, it := range in {
		itemID, err := uuid.Parse(it.ID)
		if err != nil {
			return nil, errors.New(field("items", i, "id") + " must be a uuid")
		}
		var p itemPayload
		if err := p.validate(it.Ciphertext, it.Nonce, it.SearchHmac, it.ItemType); err != nil {
			return nil, errors.New(field("items", i, "") + ": " + err.Error())
		}
		out = append(out, store.RotateItem{
			ItemID:     itemID,
			ItemType:   p.ItemType,
			Ciphertext: p.Ciphertext,
			Nonce:      p.Nonce,
			SearchHmac: p.SearchHmac,
			Favorite:   it.Favorite,
		})
	}
	return out, nil
}

func field(group string, i int, name string) string {
	if name == "" {
		return group + "[" + strconv.Itoa(i) + "]"
	}
	return group + "[" + strconv.Itoa(i) + "]." + name
}

func respondRotationError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		respondError(c, http.StatusNotFound, "vault not found")
	case errors.Is(err, store.ErrNotAdmin):
		respondError(c, http.StatusForbidden, "admin role required")
	case errors.Is(err, store.ErrWrapSet):
		respondError(c, http.StatusBadRequest,
			"vault key wraps must match the current remaining members exactly; refresh the roster and retry")
	case errors.Is(err, store.ErrItemSet):
		respondError(c, http.StatusBadRequest,
			"rotation must cover every item in the vault; re-sync and retry")
	case errors.Is(err, store.ErrSelfRevocation):
		respondError(c, http.StatusBadRequest, "use leave instead of rotating your own access away")
	case errors.Is(err, store.ErrLastAdmin):
		respondError(c, http.StatusBadRequest, "cannot revoke the last admin")
	default:
		respondError(c, http.StatusInternalServerError, "vault key rotation failed")
	}
}
