package api_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kleidion/server/internal/store"
)

// ADR-008 rotation tests: revoking a vault member must be atomic with
// re-encrypting every row of that vault under a fresh key, and any rotation
// that would leave a row decryptable with the revoked key must be refused and
// change nothing.

type itemRow struct {
	ID         string  `json:"id"`
	ItemType   int     `json:"itemType"`
	Ciphertext string  `json:"ciphertext"`
	Nonce      string  `json:"nonce"`
	SearchHmac string  `json:"searchHmac"`
	Version    int64   `json:"version"`
	Favorite   bool    `json:"favorite"`
	DeletedAt  *string `json:"deletedAt"`
}

type memberRow struct {
	UserID          string `json:"userId"`
	Email           string `json:"email"`
	Role            string `json:"role"`
	MasterPublicKey string `json:"masterPublicKey"`
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func randomB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b64(b)
}

// snapshot returns every item row of a vault, tombstones included.
func (e *testEnv) snapshot(t *testing.T, vaultID uuid.UUID) []itemRow {
	t.Helper()
	status, body := e.do(t, http.MethodGet, "/v1/items?vaultId="+vaultID.String(), nil)
	if status != http.StatusOK {
		t.Fatalf("list items: status %d body %s", status, body)
	}
	var resp struct {
		Items    []itemRow `json:"items"`
		KeyEpoch int64     `json:"keyEpoch"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode items: %v (%s)", err, body)
	}
	return resp.Items
}

func (e *testEnv) roster(t *testing.T, vaultID uuid.UUID) []memberRow {
	t.Helper()
	status, body := e.do(t, http.MethodGet, "/v1/vaults/"+vaultID.String()+"/members", nil)
	if status != http.StatusOK {
		t.Fatalf("list members: status %d body %s", status, body)
	}
	var resp struct {
		Members []memberRow `json:"members"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode members: %v (%s)", err, body)
	}
	return resp.Members
}

// addMember creates a second account directly (bypassing SRP, as newTestEnv
// does) and joins it to the vault through the real membership endpoint.
// Returns the member's id and a live session token.
func (e *testEnv) addMember(t *testing.T, vaultID uuid.UUID, role string) (uuid.UUID, string) {
	t.Helper()
	ctx := context.Background()
	email := "rotate+" + uuid.NewString()[:8] + "@kleidion.test"
	pub := make([]byte, 32)
	if _, err := rand.Read(pub); err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	u, err := e.st.CreateUser(ctx, store.CreateUserRequest{
		Email:               email,
		SrpSalt:             make([]byte, 16),
		SrpVerifier:         []byte{3},
		KdfAlgo:             "argon2id",
		KdfParams:           []byte(`{"algo":"argon2id"}`),
		MasterPublicKey:     pub,
		EncryptedPrivateKey: []byte("opaque"),
		EncryptedSymKey:     []byte("opaque"),
	})
	if err != nil {
		t.Fatalf("create member: %v", err)
	}
	deviceID, err := e.st.UpsertDevice(ctx, u.ID, "member-device", "web")
	if err != nil {
		t.Fatalf("device: %v", err)
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		t.Fatalf("token: %v", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	sum := sha256.Sum256([]byte(token))
	if _, err := e.st.CreateSession(ctx, u.ID, deviceID, sum[:], 24*time.Hour, "rotate-test"); err != nil {
		t.Fatalf("session: %v", err)
	}

	status, body := e.do(t, http.MethodPost, "/v1/vaults/"+vaultID.String()+"/members", map[string]any{
		"email":           email,
		"role":            role,
		"wrappedVaultKey": b64([]byte("sealed-for-member")),
	})
	if status != http.StatusCreated {
		t.Fatalf("add member: status %d body %s", status, body)
	}
	return u.ID, token
}

func (e *testEnv) createItem(t *testing.T, vaultID uuid.UUID, itemType int) uuid.UUID {
	t.Helper()
	status, body := e.do(t, http.MethodPost, "/v1/items", itemBody(vaultID, itemType))
	if status != http.StatusCreated {
		t.Fatalf("create item: status %d body %s", status, body)
	}
	var resp struct {
		Item struct {
			ID string `json:"id"`
		} `json:"item"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode item: %v", err)
	}
	id, err := uuid.Parse(resp.Item.ID)
	if err != nil {
		t.Fatalf("item id: %v", err)
	}
	return id
}

// rotationBody builds a complete rotation payload from the current rows.
// excludedItemIDs are deliberately dropped to exercise the completeness check.
func rotationBody(items []itemRow, members []memberRow, revoked string, excludeItems ...string) map[string]any {
	skip := map[string]bool{}
	for _, id := range excludeItems {
		skip[id] = true
	}
	newItems := make([]map[string]any, 0, len(items))
	for _, it := range items {
		if skip[it.ID] {
			continue
		}
		newItems = append(newItems, map[string]any{
			"id":         it.ID,
			"itemType":   it.ItemType,
			"ciphertext": randomB64(64),
			"nonce":      randomB64(24),
			"searchHmac": randomB64(32),
			"favorite":   it.Favorite,
		})
	}
	wraps := make([]map[string]any, 0, len(members))
	for _, m := range members {
		if m.UserID == revoked {
			continue
		}
		wraps = append(wraps, map[string]any{
			"userId":          m.UserID,
			"wrappedVaultKey": b64([]byte("new-seal-for-" + m.UserID)),
		})
	}
	body := map[string]any{
		"encryptedMeta": randomB64(48),
		"nonce":         randomB64(24),
		"members":       wraps,
		"items":         newItems,
	}
	if revoked != "" {
		body["revokedUserId"] = revoked
	}
	return body
}

// dropWrap removes one member's wrap from an otherwise complete body.
func dropWrap(wraps []map[string]any, userID string) []map[string]any {
	out := make([]map[string]any, 0, len(wraps))
	for _, w := range wraps {
		if w["userId"] != userID {
			out = append(out, w)
		}
	}
	return out
}

func countHistory(t *testing.T, st *store.Store, vaultID uuid.UUID) int {
	t.Helper()
	var n int
	if err := st.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM item_versions iv JOIN items i ON i.id = iv.item_id WHERE i.vault_id = $1`,
		vaultID).Scan(&n); err != nil {
		t.Fatalf("count item_versions: %v", err)
	}
	return n
}

func TestIntegrationRotationRevokesAndReencrypts(t *testing.T) {
	e := newTestEnv(t)
	vaultID := e.createVault(t)

	ids := []uuid.UUID{
		e.createItem(t, vaultID, 1),
		e.createItem(t, vaultID, 1),
		e.createItem(t, vaultID, 2),
	}
	// An update archives the previous ciphertext, so history exists pre-rotation.
	if status, body := e.do(t, http.MethodPut, "/v1/items/"+ids[0].String(), itemBody(vaultID, 1)); status != http.StatusOK {
		t.Fatalf("update item: status %d body %s", status, body)
	}
	if n := countHistory(t, e.st, vaultID); n != 1 {
		t.Fatalf("item_versions before rotation = %d, want 1", n)
	}
	// A tombstone still holds old-key ciphertext, so rotation must cover it.
	if status, body := e.do(t, http.MethodDelete, "/v1/items/"+ids[2].String(), nil); status != http.StatusOK {
		t.Fatalf("delete item: status %d body %s", status, body)
	}

	bobID, bobToken := e.addMember(t, vaultID, "write")
	aliceToken := e.token
	before := e.snapshot(t, vaultID)
	if len(before) != 3 {
		t.Fatalf("item rows = %d, want 3 (2 live + 1 tombstone)", len(before))
	}
	members := e.roster(t, vaultID)
	if len(members) != 2 {
		t.Fatalf("members = %d, want 2", len(members))
	}
	// The admin needs each remaining member's public key to re-seal the key.
	for _, m := range members {
		if kb, err := hex.DecodeString(m.MasterPublicKey); err != nil || len(kb) != 32 {
			t.Fatalf("member %s masterPublicKey = %q, want 32 raw bytes as hex", m.Email, m.MasterPublicKey)
		}
	}
	var maxBefore int64
	oldCT := map[string]string{}
	for _, it := range before {
		oldCT[it.ID] = it.Ciphertext
		if it.Version > maxBefore {
			maxBefore = it.Version
		}
	}

	status, body := e.do(t, http.MethodPost, "/v1/vaults/"+vaultID.String()+"/rotate-key",
		rotationBody(before, members, bobID.String()))
	if status != http.StatusOK {
		t.Fatalf("rotate: status %d body %s", status, body)
	}
	var res struct {
		Vault struct {
			KeyEpoch int64  `json:"keyEpoch"`
			Role     string `json:"role"`
		} `json:"vault"`
		ServerVersion int64 `json:"serverVersion"`
		KeyEpoch      int64 `json:"keyEpoch"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatalf("decode rotate: %v (%s)", err, body)
	}
	if res.KeyEpoch != 2 || res.Vault.KeyEpoch != 2 {
		t.Fatalf("keyEpoch = %d (vault %d), want 2", res.KeyEpoch, res.Vault.KeyEpoch)
	}
	if res.Vault.Role != "admin" {
		t.Fatalf("rotating caller role = %q, want admin", res.Vault.Role)
	}

	after := e.snapshot(t, vaultID)
	if len(after) != len(before) {
		t.Fatalf("item rows after rotation = %d, want %d", len(after), len(before))
	}
	seen := map[int64]bool{}
	for _, it := range after {
		if it.Ciphertext == oldCT[it.ID] {
			t.Fatalf("item %s kept its pre-rotation ciphertext", it.ID)
		}
		if it.Version <= maxBefore {
			t.Fatalf("item %s version = %d, want > %d (subscribers must re-sync)", it.ID, it.Version, maxBefore)
		}
		if seen[it.Version] {
			t.Fatalf("duplicate version %d after rotation", it.Version)
		}
		seen[it.Version] = true
	}
	if res.ServerVersion != maxBefore+int64(len(after)) {
		t.Fatalf("serverVersion = %d, want %d", res.ServerVersion, maxBefore+int64(len(after)))
	}

	// Archived ciphertexts under the revoked key are gone.
	if n := countHistory(t, e.st, vaultID); n != 0 {
		t.Fatalf("item_versions after rotation = %d, want 0 (purged)", n)
	}

	// Roster: Bob revoked, Alice still admin; every vault view reports epoch 2.
	members = e.roster(t, vaultID)
	if len(members) != 1 || members[0].Role != "admin" || members[0].UserID != e.userID.String() {
		t.Fatalf("roster after rotation = %+v, want only the rotating admin", members)
	}

	// Bob keeps no read path into the vault.
	e.token = bobToken
	if status, body := e.do(t, http.MethodGet, "/v1/items?vaultId="+vaultID.String(), nil); status != http.StatusBadRequest {
		t.Fatalf("revoked member GET /v1/items: status %d, want 400 (body %s)", status, body)
	}
	if status, body := e.do(t, http.MethodGet, "/v1/sync/changes?vaultId="+vaultID.String()+"&since=0", nil); status != http.StatusBadRequest {
		t.Fatalf("revoked member sync: status %d, want 400 (body %s)", status, body)
	}
	if status, body := e.do(t, http.MethodGet, "/v1/vaults/"+vaultID.String()+"/members", nil); status != http.StatusBadRequest {
		t.Fatalf("revoked member roster: status %d, want 400 (body %s)", status, body)
	}
	status, body = e.do(t, http.MethodGet, "/v1/vaults", nil)
	if status != http.StatusOK {
		t.Fatalf("revoked member list vaults: status %d", status)
	}
	var bobVaults struct {
		Vaults []struct {
			ID string `json:"id"`
		} `json:"vaults"`
	}
	if err := json.Unmarshal(body, &bobVaults); err != nil {
		t.Fatalf("decode bob vaults: %v", err)
	}
	for _, v := range bobVaults.Vaults {
		if v.ID == vaultID.String() {
			t.Fatalf("revoked member still lists vault %s", vaultID)
		}
	}
	e.token = aliceToken

	// Alice's sync feed carries the new epoch and the rewritten rows.
	status, body = e.do(t, http.MethodGet, "/v1/sync/changes?vaultId="+vaultID.String()+"&since="+strconv.FormatInt(maxBefore, 10), nil)
	if status != http.StatusOK {
		t.Fatalf("sync after rotation: status %d body %s", status, body)
	}
	var sc struct {
		Changes  []itemRow `json:"changes"`
		KeyEpoch int64     `json:"keyEpoch"`
	}
	if err := json.Unmarshal(body, &sc); err != nil {
		t.Fatalf("decode sync: %v", err)
	}
	if sc.KeyEpoch != 2 {
		t.Fatalf("sync keyEpoch = %d, want 2", sc.KeyEpoch)
	}
	if len(sc.Changes) != len(after) {
		t.Fatalf("sync since=%d returned %d changes, want %d (all rows must look new)",
			maxBefore, len(sc.Changes), len(after))
	}
}

func TestIntegrationRotationRefusesPartialSets(t *testing.T) {
	e := newTestEnv(t)
	vaultID := e.createVault(t)
	for i := 0; i < 2; i++ {
		e.createItem(t, vaultID, 2)
	}
	bobID, _ := e.addMember(t, vaultID, "read")

	items := e.snapshot(t, vaultID)
	members := e.roster(t, vaultID)
	path := "/v1/vaults/" + vaultID.String() + "/rotate-key"

	// 1. One item withheld → the vault would keep an old-key row.
	body := rotationBody(items, members, "", items[0].ID)
	if status, resp := e.do(t, http.MethodPost, path, body); status != http.StatusBadRequest {
		t.Fatalf("missing item: status %d, want 400 (body %s)", status, resp)
	}
	// 2. A wrap for someone not in the roster.
	body = rotationBody(items, members, "")
	body["members"] = append(body["members"].([]map[string]any),
		map[string]any{"userId": uuid.NewString(), "wrappedVaultKey": randomB64(48)})
	if status, resp := e.do(t, http.MethodPost, path, body); status != http.StatusBadRequest {
		t.Fatalf("extra wrap: status %d, want 400 (body %s)", status, resp)
	}
	// 3. Dropping Bob's wrap WITHOUT naming him as revoked would lock him out
	//    silently; only revokedUserId may remove a member.
	body = rotationBody(items, members, "")
	body["members"] = dropWrap(body["members"].([]map[string]any), bobID.String())
	if status, resp := e.do(t, http.MethodPost, path, body); status != http.StatusBadRequest {
		t.Fatalf("unsignalled member drop: status %d, want 400 (body %s)", status, resp)
	}

	// A rejected rotation must be a no-op, row for row.
	unchanged := e.snapshot(t, vaultID)
	if len(unchanged) != len(items) {
		t.Fatalf("row count changed after rejected rotations")
	}
	for i, it := range unchanged {
		if it.Ciphertext != items[i].Ciphertext || it.Version != items[i].Version {
			t.Fatalf("item %s mutated by a rejected rotation", it.ID)
		}
	}
	if got := len(e.roster(t, vaultID)); got != len(members) {
		t.Fatalf("roster changed after rejected rotation: %d vs %d", got, len(members))
	}
	if epoch, err := e.st.GetVaultKeyEpoch(context.Background(), vaultID); err != nil || epoch != 1 {
		t.Fatalf("key epoch = %d (err %v), want 1", epoch, err)
	}

	// The same vault rotates cleanly once the sets are complete.
	if status, resp := e.do(t, http.MethodPost, path, rotationBody(unchanged, members, bobID.String())); status != http.StatusOK {
		t.Fatalf("valid rotation: status %d body %s", status, resp)
	}
}

func TestIntegrationRotationAuthorization(t *testing.T) {
	e := newTestEnv(t)
	vaultID := e.createVault(t)
	e.createItem(t, vaultID, 1)
	bobID, bobToken := e.addMember(t, vaultID, "write")
	aliceToken := e.token

	items := e.snapshot(t, vaultID)
	members := e.roster(t, vaultID)
	path := "/v1/vaults/" + vaultID.String() + "/rotate-key"

	// A write member may not rotate (only admins hold the full plaintext set).
	e.token = bobToken
	if status, body := e.do(t, http.MethodPost, path, rotationBody(items, members, "")); status != http.StatusForbidden {
		t.Fatalf("non-admin rotate: status %d, want 403 (body %s)", status, body)
	}
	e.token = aliceToken

	// An admin may not rotate themselves out.
	if status, body := e.do(t, http.MethodPost, path, rotationBody(items, members, e.userID.String())); status != http.StatusBadRequest {
		t.Fatalf("self-revoke: status %d, want 400 (body %s)", status, body)
	}

	// A vault the caller is not a member of is answered as absent (404), so
	// rotation cannot be used to probe which vault ids exist.
	if status, _ := e.do(t, http.MethodPost, "/v1/vaults/"+uuid.NewString()+"/rotate-key",
		rotationBody(items, members, bobID.String())); status != http.StatusNotFound {
		t.Fatalf("unmembered vault: status %d, want 404", status)
	}
}
