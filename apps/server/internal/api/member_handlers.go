package api

import (
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/kleidion/server/internal/store"
)

// memberHandler serves the Phase 4 shared-vault membership endpoints.
// Zero-knowledge: the server manages roles and stores each member's sealed
// vault key (opaque); it can never read the vault key itself.
type memberHandler struct {
	st *store.Store
}

func registerMemberRoutes(rg *gin.RouterGroup, st *store.Store) {
	h := &memberHandler{st: st}
	g := rg.Group("/vaults/:id/members")
	{
		g.GET("", h.list)
		g.POST("", h.add)
		g.PATCH("/:userId", h.patchRole)
		g.DELETE("/:userId", h.remove)
	}
	rg.GET("/users/lookup", h.lookupUser)
}

type memberWire struct {
	UserID    string    `json:"userId"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"createdAt"`
}

// requireAdmin resolves the caller's role and demands admin. Returns
// ok=false after writing the error response.
func requireAdmin(c *gin.Context, st *store.Store, vaultID uuid.UUID) bool {
	role, err := st.GetVaultMembership(c.Request.Context(), vaultID, ctxUserID(c))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			respondError(c, http.StatusNotFound, "vault not found")
			return false
		}
		respondError(c, http.StatusInternalServerError, "membership check failed")
		return false
	}
	if role != "admin" {
		respondError(c, http.StatusForbidden, "admin role required")
		return false
	}
	return true
}

func parseVaultParam(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		respondError(c, http.StatusBadRequest, "id must be a uuid")
		return uuid.Nil, false
	}
	return id, true
}

func validRole(r string) bool { return r == "admin" || r == "write" || r == "read" }

// list returns the vault's members (any member can see the roster).
func (h *memberHandler) list(c *gin.Context) {
	vaultID, ok := parseVaultParam(c)
	if !ok {
		return
	}
	if _, ok := requireMembership(c, h.st, vaultID, false); !ok {
		return
	}
	members, err := h.st.ListVaultMembers(c.Request.Context(), vaultID)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "failed to list members")
		return
	}
	out := make([]memberWire, 0, len(members))
	for _, m := range members {
		out = append(out, memberWire{m.UserID.String(), m.Email, m.Role, m.CreatedAt})
	}
	c.JSON(http.StatusOK, gin.H{"members": out})
}

type addMemberRequest struct {
	Email           string `json:"email"`
	Role            string `json:"role"`
	WrappedVaultKey string `json:"wrappedVaultKey"`
}

// add grants an existing user vault access with a client-sealed vault key.
func (h *memberHandler) add(c *gin.Context) {
	vaultID, ok := parseVaultParam(c)
	if !ok {
		return
	}
	if !requireAdmin(c, h.st, vaultID) {
		return
	}
	var req addMemberRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || !validRole(req.Role) {
		respondError(c, http.StatusBadRequest, "email and role (admin|write|read) are required")
		return
	}
	wrapped, err := decodeB64Field(req.WrappedVaultKey, "wrappedVaultKey", false, 0)
	if err != nil {
		respondError(c, http.StatusBadRequest, err.Error())
		return
	}
	target, err := h.st.GetUserByEmail(c.Request.Context(), email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			respondError(c, http.StatusNotFound, "no Kleidion user with that email")
			return
		}
		respondError(c, http.StatusInternalServerError, "member lookup failed")
		return
	}
	if err := h.st.AddVaultKey(c.Request.Context(), vaultID, target.ID, wrapped, req.Role); err != nil {
		respondError(c, http.StatusInternalServerError, "failed to add member")
		return
	}
	c.JSON(http.StatusCreated, gin.H{"member": memberWire{target.ID.String(), target.Email, req.Role, time.Now().UTC()}})
}

type patchRoleRequest struct {
	Role string `json:"role"`
}

// patchRole changes a member's role; refuses to orphan the vault by
// demoting the only admin.
func (h *memberHandler) patchRole(c *gin.Context) {
	vaultID, ok := parseVaultParam(c)
	if !ok {
		return
	}
	if !requireAdmin(c, h.st, vaultID) {
		return
	}
	userID, err := uuid.Parse(c.Param("userId"))
	if err != nil {
		respondError(c, http.StatusBadRequest, "userId must be a uuid")
		return
	}
	var req patchRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil || !validRole(req.Role) {
		respondError(c, http.StatusBadRequest, "role must be admin, write, or read")
		return
	}
	current, err := h.st.GetVaultMembership(c.Request.Context(), vaultID, userID)
	if err != nil {
		respondError(c, http.StatusNotFound, "member not found")
		return
	}
	if current == "admin" && req.Role != "admin" {
		admins, err := h.st.CountVaultAdmins(c.Request.Context(), vaultID)
		if err != nil {
			respondError(c, http.StatusInternalServerError, "admin count failed")
			return
		}
		if admins <= 1 {
			respondError(c, http.StatusBadRequest, "cannot demote the last admin")
			return
		}
	}
	if err := h.st.UpdateVaultKeyRole(c.Request.Context(), vaultID, userID, req.Role); err != nil {
		respondError(c, http.StatusInternalServerError, "failed to update role")
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// remove revokes access; admins can remove anyone, non-admins may remove
// themselves (leave), and the last admin may not leave.
func (h *memberHandler) remove(c *gin.Context) {
	vaultID, ok := parseVaultParam(c)
	if !ok {
		return
	}
	callerRole, ok := requireMembership(c, h.st, vaultID, false)
	if !ok {
		return
	}
	userID, err := uuid.Parse(c.Param("userId"))
	if err != nil {
		respondError(c, http.StatusBadRequest, "userId must be a uuid")
		return
	}
	self := userID == ctxUserID(c)
	if !self && callerRole != "admin" {
		respondError(c, http.StatusForbidden, "only admins can remove other members")
		return
	}
	targetRole, err := h.st.GetVaultMembership(c.Request.Context(), vaultID, userID)
	if err != nil {
		respondError(c, http.StatusNotFound, "member not found")
		return
	}
	if targetRole == "admin" {
		admins, err := h.st.CountVaultAdmins(c.Request.Context(), vaultID)
		if err != nil {
			respondError(c, http.StatusInternalServerError, "admin count failed")
			return
		}
		if admins <= 1 {
			respondError(c, http.StatusBadRequest, "cannot remove the last admin")
			return
		}
	}
	if err := h.st.RemoveVaultKey(c.Request.Context(), vaultID, userID); err != nil {
		respondError(c, http.StatusInternalServerError, "failed to remove member")
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// lookupUser returns just enough of a stranger's identity to seal a vault
// key for them: id, email, X25519 public key. No private material.
func (h *memberHandler) lookupUser(c *gin.Context) {
	email := strings.ToLower(strings.TrimSpace(c.Query("email")))
	if email == "" {
		respondError(c, http.StatusBadRequest, "email query param required")
		return
	}
	u, err := h.st.GetUserByEmail(c.Request.Context(), email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			respondError(c, http.StatusNotFound, "no Kleidion user with that email")
			return
		}
		respondError(c, http.StatusInternalServerError, "lookup failed")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"userId":          u.ID.String(),
		"email":           u.Email,
		"masterPublicKey": hex.EncodeToString(u.MasterPublicKey),
	})
}
