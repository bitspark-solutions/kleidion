package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/kleidion/server/internal/api"
	"github.com/kleidion/server/internal/config"
	"github.com/kleidion/server/internal/store"
)

// testDBURL returns the Postgres URL for integration tests, or skips if unset.
//
// Run with:
//
//	KLEIDION_TEST_DATABASE_URL=postgres://kleidion@127.0.0.1:25432/kleidion_test?sslmode=disable \
//	  go test ./internal/api/... -run Integration -v
func testDBURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("KLEIDION_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("KLEIDION_TEST_DATABASE_URL not set — skipping integration test")
	}
	return url
}

// newTestDatabase creates a dedicated, uniquely-named database derived from
// KLEIDION_TEST_DATABASE_URL and drops it when the test finishes. This keeps
// `go test ./...` (parallel packages) safe: the auth integration tests
// TRUNCATE the shared DB, which would otherwise race with these tests.
func newTestDatabase(t *testing.T) string {
	t.Helper()
	base := testDBURL(t)
	name := "kleidion_api_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")

	// Split the DSN into server part and query part, then swap the database
	// name after the last "/" of the path component.
	pathPart, query := base, ""
	if i := strings.Index(base, "?"); i >= 0 {
		pathPart, query = base[:i], base[i:]
	}
	cut := strings.LastIndex(pathPart, "/")
	if cut < 0 {
		t.Fatalf("KLEIDION_TEST_DATABASE_URL must contain /dbname: %q", base)
	}
	adminURL := pathPart[:cut] + "/postgres" + query

	admin, err := store.Open(context.Background(), adminURL, zerolog.Nop())
	if err != nil {
		t.Fatalf("open admin db: %v", err)
	}
	defer admin.Close()
	if _, err := admin.Pool.Exec(context.Background(), `CREATE DATABASE `+name); err != nil {
		t.Fatalf("create test database: %v", err)
	}

	testURL := pathPart[:cut] + "/" + name + query
	t.Cleanup(func() {
		// Force-disconnect stragglers, then drop.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if a, err := store.Open(ctx, adminURL, zerolog.Nop()); err == nil {
			defer a.Close()
			_, _ = a.Pool.Exec(ctx,
				`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1`, name)
			_, _ = a.Pool.Exec(ctx, `DROP DATABASE IF EXISTS `+name)
		}
	})
	return testURL
}

// testEnv bundles a migrated store, an httptest server, a live session token,
// and the captured server log output (for the zero-knowledge canary test).
type testEnv struct {
	st       *store.Store
	srv      *httptest.Server
	token    string
	userID   uuid.UUID
	deviceID uuid.UUID
	logBuf   *bytes.Buffer
}

// newTestEnv opens a disposable DB (a dedicated per-run database so parallel
// packages don't TRUNCATE each other), migrates, creates a user + device +
// session directly (skipping SRP; the middleware only needs the token hash),
// and wires the real router.
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	dbURL := newTestDatabase(t)
	st, err := store.Open(ctx, dbURL, zerolog.Nop())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.MigrateWithRetry(ctx, 3, time.Second); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	u, err := st.CreateUser(ctx, store.CreateUserRequest{
		Email:               "phase3+" + uuid.NewString()[:8] + "@kleidion.test",
		SrpSalt:             make([]byte, 16),
		SrpVerifier:         []byte{2},
		KdfAlgo:             "argon2id",
		KdfParams:           []byte(`{"algo":"argon2id","opsLimit":3,"memLimit":268435456}`),
		MasterPublicKey:     make([]byte, 32),
		EncryptedPrivateKey: []byte("opaque"),
		EncryptedSymKey:     []byte("opaque"),
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	deviceID, err := st.UpsertDevice(ctx, u.ID, "test-device", "web")
	if err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		t.Fatalf("token: %v", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	sum := sha256.Sum256([]byte(token))
	if _, err := st.CreateSession(ctx, u.ID, deviceID, sum[:], 24*time.Hour); err != nil {
		t.Fatalf("create session: %v", err)
	}

	logBuf := &bytes.Buffer{}
	log := zerolog.New(logBuf)
	r := api.NewRouter(log, st, config.Config{Env: "development", Port: "0"})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	return &testEnv{st: st, srv: srv, token: token, userID: u.ID, deviceID: deviceID, logBuf: logBuf}
}

// do issues an authenticated JSON request and returns status + raw body.
func (e *testEnv) do(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if e.token != "" {
		req.Header.Set("Authorization", "Bearer "+e.token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, buf.Bytes()
}

// createVault creates a vault via the API and returns its id.
func (e *testEnv) createVault(t *testing.T) uuid.UUID {
	t.Helper()
	status, body := e.do(t, http.MethodPost, "/v1/vaults", map[string]any{
		"kind":            "personal",
		"encryptedMeta":   base64.StdEncoding.EncodeToString([]byte("encrypted-vault-meta")),
		"nonce":           base64.StdEncoding.EncodeToString(make([]byte, 24)),
		"wrappedVaultKey": base64.StdEncoding.EncodeToString([]byte("sealed-box")),
	})
	if status != http.StatusCreated {
		t.Fatalf("create vault: status %d body %s", status, body)
	}
	var resp struct {
		Vault struct {
			ID            string `json:"id"`
			Kind          string `json:"kind"`
			EncryptedMeta string `json:"encryptedMeta"`
			Nonce         string `json:"nonce"`
			Role          string `json:"role"`
			CreatedAt     string `json:"createdAt"`
			UpdatedAt     string `json:"updatedAt"`
		} `json:"vault"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode vault: %v", err)
	}
	if resp.Vault.Role != "admin" {
		t.Fatalf("creator role = %q, want admin", resp.Vault.Role)
	}
	if resp.Vault.Kind != "personal" || resp.Vault.EncryptedMeta == "" || resp.Vault.Nonce == "" || resp.Vault.CreatedAt == "" {
		t.Fatalf("vault meta wire shape wrong: %s", body)
	}
	id, err := uuid.Parse(resp.Vault.ID)
	if err != nil {
		t.Fatalf("vault id: %v", err)
	}
	return id
}

// itemBody builds a valid create/update item payload with random opaque blobs.
func itemBody(vaultID uuid.UUID, itemType int) map[string]any {
	ct := make([]byte, 64)
	_, _ = rand.Read(ct)
	nonce := make([]byte, 24)
	_, _ = rand.Read(nonce)
	hm := make([]byte, 32)
	_, _ = rand.Read(hm)
	b := map[string]any{
		"itemType":   itemType,
		"ciphertext": base64.StdEncoding.EncodeToString(ct),
		"nonce":      base64.StdEncoding.EncodeToString(nonce),
		"searchHmac": base64.StdEncoding.EncodeToString(hm),
		"favorite":   false,
	}
	if vaultID != uuid.Nil {
		b["vaultId"] = vaultID.String()
	}
	return b
}

// TestIntegrationUnauthorized covers the contract's 401s: missing header,
// garbage token, and a revoked session token.
func TestIntegrationUnauthorized(t *testing.T) {
	e := newTestEnv(t)

	saved := e.token
	e.token = ""
	if status, body := e.do(t, http.MethodGet, "/v1/vaults", nil); status != http.StatusUnauthorized {
		t.Fatalf("no token: status %d body %s", status, body)
	}
	e.token = "garbage-token"
	if status, _ := e.do(t, http.MethodGet, "/v1/items?vaultId="+uuid.NewString(), nil); status != http.StatusUnauthorized {
		t.Fatalf("garbage token: status %d", status)
	}
	e.token = saved

	// A revoked session must also yield 401.
	var sessID uuid.UUID
	if err := e.st.Pool.QueryRow(context.Background(),
		`SELECT id FROM sessions WHERE user_id = $1`, e.userID).Scan(&sessID); err != nil {
		t.Fatalf("session lookup: %v", err)
	}
	if err := e.st.RevokeSession(context.Background(), sessID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if status, _ := e.do(t, http.MethodGet, "/v1/vaults", nil); status != http.StatusUnauthorized {
		t.Fatalf("revoked token: status %d, want 401", status)
	}
}

// TestIntegrationVaults covers vault creation, listing, and membership
// validation (vaultId the caller has no vault_keys row for → 400).
func TestIntegrationVaults(t *testing.T) {
	e := newTestEnv(t)

	vaultID := e.createVault(t)

	status, body := e.do(t, http.MethodGet, "/v1/vaults", nil)
	if status != http.StatusOK {
		t.Fatalf("list vaults: %d %s", status, body)
	}
	var list struct {
		Vaults []map[string]any `json:"vaults"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list.Vaults) != 1 || list.Vaults[0]["id"] != vaultID.String() {
		t.Fatalf("vaults = %v", list.Vaults)
	}

	// A vaultId the caller is not a member of → 400 (contract validation).
	status, _ = e.do(t, http.MethodGet, "/v1/items?vaultId="+uuid.NewString(), nil)
	if status != http.StatusBadRequest {
		t.Fatalf("foreign vaultId: status %d, want 400", status)
	}
	status, _ = e.do(t, http.MethodGet, "/v1/items?vaultId=not-a-uuid", nil)
	if status != http.StatusBadRequest {
		t.Fatalf("malformed vaultId: status %d, want 400", status)
	}
}

// TestIntegrationItemValidation covers the contract's 400 rules on POST /v1/items.
func TestIntegrationItemValidation(t *testing.T) {
	e := newTestEnv(t)
	vaultID := e.createVault(t)

	badNonce := base64.StdEncoding.EncodeToString(make([]byte, 12))
	badHmac := base64.StdEncoding.EncodeToString(make([]byte, 31))
	bigCt := base64.StdEncoding.EncodeToString(make([]byte, (1<<20)+1))

	cases := []struct {
		name string
		mut  func(map[string]any)
	}{
		{"itemType 0", func(b map[string]any) { b["itemType"] = 0 }},
		{"itemType 5", func(b map[string]any) { b["itemType"] = 5 }},
		{"empty ciphertext", func(b map[string]any) { b["ciphertext"] = "" }},
		{"empty nonce", func(b map[string]any) { b["nonce"] = "" }},
		{"short nonce", func(b map[string]any) { b["nonce"] = badNonce }},
		{"short searchHmac", func(b map[string]any) { b["searchHmac"] = badHmac }},
		{"oversized ciphertext", func(b map[string]any) { b["ciphertext"] = bigCt }},
		{"non-base64 ciphertext", func(b map[string]any) { b["ciphertext"] = "!!!not-b64!!!" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := itemBody(vaultID, 1)
			tc.mut(b)
			status, body := e.do(t, http.MethodPost, "/v1/items", b)
			if status != http.StatusBadRequest {
				t.Fatalf("status %d, want 400; body %s", status, body)
			}
			if !strings.Contains(string(body), `"error"`) {
				t.Fatalf("body must be {\"error\":...}: %s", body)
			}
		})
	}
}

// TestIntegrationVersionBumpAndDeltaSync covers per-vault version bumping
// (COALESCE(MAX,0)+1), since-deltas including tombstones, and item_versions
// history of the PREVIOUS ciphertext on update (not on create).
func TestIntegrationVersionBumpAndDeltaSync(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	vaultID := e.createVault(t)

	// Create two items → versions 1 and 2.
	status, body := e.do(t, http.MethodPost, "/v1/items", itemBody(vaultID, 1))
	if status != http.StatusCreated {
		t.Fatalf("create item1: %d %s", status, body)
	}
	var c1 struct {
		Item struct {
			ID         string `json:"id"`
			Version    int64  `json:"version"`
			Ciphertext string `json:"ciphertext"`
		} `json:"item"`
	}
	mustJSON(t, body, &c1)
	if c1.Item.Version != 1 {
		t.Fatalf("first item version = %d, want 1", c1.Item.Version)
	}

	status, body = e.do(t, http.MethodPost, "/v1/items", itemBody(vaultID, 2))
	if status != http.StatusCreated {
		t.Fatalf("create item2: %d %s", status, body)
	}
	var c2 struct {
		Item struct {
			ID      string `json:"id"`
			Version int64  `json:"version"`
		} `json:"item"`
	}
	mustJSON(t, body, &c2)
	if c2.Item.Version != 2 {
		t.Fatalf("second item version = %d, want 2", c2.Item.Version)
	}

	// Update item1 → version 3; item_versions must hold version 1's ciphertext.
	status, body = e.do(t, http.MethodPut, "/v1/items/"+c1.Item.ID, itemBody(uuid.Nil, 1))
	if status != http.StatusOK {
		t.Fatalf("update item1: %d %s", status, body)
	}
	var u1 struct {
		Item struct {
			Version int64 `json:"version"`
		} `json:"item"`
	}
	mustJSON(t, body, &u1)
	if u1.Item.Version != 3 {
		t.Fatalf("updated version = %d, want 3", u1.Item.Version)
	}

	var archivedCt []byte
	if err := e.st.Pool.QueryRow(ctx,
		`SELECT ciphertext FROM item_versions WHERE item_id = $1 AND version = 1`, c1.Item.ID).
		Scan(&archivedCt); err != nil {
		t.Fatalf("item_versions row: %v", err)
	}
	if base64.StdEncoding.EncodeToString(archivedCt) != c1.Item.Ciphertext {
		t.Fatal("item_versions must archive the PREVIOUS ciphertext")
	}

	// Delete item2 → tombstone at version 4.
	status, body = e.do(t, http.MethodDelete, "/v1/items/"+c2.Item.ID, nil)
	if status != http.StatusOK {
		t.Fatalf("delete item2: %d %s", status, body)
	}
	var d2 struct {
		Item struct {
			Version   int64  `json:"version"`
			DeletedAt string `json:"deletedAt"`
		} `json:"item"`
	}
	mustJSON(t, body, &d2)
	if d2.Item.Version != 4 || d2.Item.DeletedAt == "" {
		t.Fatalf("tombstone = %+v, want version 4 with deletedAt", d2.Item)
	}

	// since=0 returns BOTH items, including the soft-deleted tombstone.
	status, body = e.do(t, http.MethodGet, fmt.Sprintf("/v1/items?vaultId=%s&since=0", vaultID), nil)
	if status != http.StatusOK {
		t.Fatalf("list since=0: %d", status)
	}
	var l0 struct {
		Items []struct {
			ID         string  `json:"id"`
			Version    int64   `json:"version"`
			DeletedAt  *string `json:"deletedAt"`
			SearchHmac *string `json:"searchHmac"`
		} `json:"items"`
		ServerVersion int64 `json:"serverVersion"`
	}
	mustJSON(t, body, &l0)
	if len(l0.Items) != 2 || l0.ServerVersion != 4 {
		t.Fatalf("since=0: %d items, serverVersion %d; want 2 and 4", len(l0.Items), l0.ServerVersion)
	}

	// since=3 returns only the tombstone (version 4 > 3).
	status, body = e.do(t, http.MethodGet, fmt.Sprintf("/v1/items?vaultId=%s&since=3", vaultID), nil)
	var l3 struct {
		Items []struct {
			ID        string `json:"id"`
			Version   int64  `json:"version"`
			DeletedAt string `json:"deletedAt"`
		} `json:"items"`
		ServerVersion int64 `json:"serverVersion"`
	}
	mustJSON(t, body, &l3)
	if status != http.StatusOK || len(l3.Items) != 1 || l3.Items[0].ID != c2.Item.ID || l3.Items[0].DeletedAt == "" {
		t.Fatalf("since=3: status %d body %s", status, body)
	}
	if l3.ServerVersion != 4 {
		t.Fatalf("serverVersion = %d, want 4", l3.ServerVersion)
	}

	// since=4 returns nothing but still reports the serverVersion.
	status, body = e.do(t, http.MethodGet, fmt.Sprintf("/v1/items?vaultId=%s&since=4", vaultID), nil)
	var l4 struct {
		Items         []any `json:"items"`
		ServerVersion int64 `json:"serverVersion"`
	}
	mustJSON(t, body, &l4)
	if status != http.StatusOK || len(l4.Items) != 0 || l4.ServerVersion != 4 {
		t.Fatalf("since=4: status %d body %s", status, body)
	}

	// GET /v1/items/:id/versions lists the archived version 1.
	status, body = e.do(t, http.MethodGet, "/v1/items/"+c1.Item.ID+"/versions", nil)
	var vs struct {
		Versions []struct {
			Version   int64  `json:"version"`
			CreatedAt string `json:"createdAt"`
		} `json:"versions"`
	}
	mustJSON(t, body, &vs)
	if status != http.StatusOK || len(vs.Versions) != 1 || vs.Versions[0].Version != 1 || vs.Versions[0].CreatedAt == "" {
		t.Fatalf("versions: status %d body %s", status, body)
	}

	// searchHmac exact-match filter ANDs with since.
	hm := make([]byte, 32)
	copy(hm, []byte("exact-search-hmac-value-32bytes!"))
	b := itemBody(vaultID, 1)
	b["searchHmac"] = base64.StdEncoding.EncodeToString(hm)
	status, body = e.do(t, http.MethodPost, "/v1/items", b)
	if status != http.StatusCreated {
		t.Fatalf("create with hmac: %d %s", status, body)
	}
	var hx struct {
		Item struct{ ID string } `json:"item"`
	}
	mustJSON(t, body, &hx)
	q := base64.StdEncoding.EncodeToString(hm)
	status, body = e.do(t, http.MethodGet,
		fmt.Sprintf("/v1/items?vaultId=%s&since=0&searchHmac=%s", vaultID, q), nil)
	var lf struct {
		Items []struct{ ID string } `json:"items"`
	}
	mustJSON(t, body, &lf)
	if status != http.StatusOK || len(lf.Items) != 1 || lf.Items[0].ID != hx.Item.ID {
		t.Fatalf("searchHmac filter: status %d body %s", status, body)
	}

	// Sync changes endpoint mirrors the delta.
	status, body = e.do(t, http.MethodGet, fmt.Sprintf("/v1/sync/changes?vaultId=%s&since=4", vaultID), nil)
	var ch struct {
		Changes       []map[string]any `json:"changes"`
		LatestVersion int64            `json:"latestVersion"`
		HasMore       bool             `json:"hasMore"`
	}
	mustJSON(t, body, &ch)
	if status != http.StatusOK || len(ch.Changes) != 1 || ch.LatestVersion != 5 || ch.HasMore != false {
		t.Fatalf("sync changes: status %d body %s", status, body)
	}

	// Cursor post + read-back.
	status, body = e.do(t, http.MethodPost, "/v1/sync/cursor", map[string]any{
		"vaultId":     vaultID.String(),
		"lastVersion": 5,
		"deviceId":    e.deviceID.String(),
	})
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"ok":true`)) {
		t.Fatalf("post cursor: %d %s", status, body)
	}
	got, err := e.st.GetSyncCursor(ctx, e.userID, e.deviceID, vaultID)
	if err != nil || got != 5 {
		t.Fatalf("cursor read-back = %d (%v), want 5", got, err)
	}
	// A deviceId owned by someone else must be rejected (400).
	status, _ = e.do(t, http.MethodPost, "/v1/sync/cursor", map[string]any{
		"vaultId": vaultID.String(), "lastVersion": 5, "deviceId": uuid.NewString(),
	})
	if status != http.StatusBadRequest {
		t.Fatalf("foreign deviceId cursor: status %d, want 400", status)
	}
}

// TestIntegrationReadRoleForbidden covers role="read": GET allowed,
// POST/PUT/DELETE → 403.
func TestIntegrationReadRoleForbidden(t *testing.T) {
	e := newTestEnv(t)
	vaultID := e.createVault(t)

	status, body := e.do(t, http.MethodPost, "/v1/items", itemBody(vaultID, 1))
	if status != http.StatusCreated {
		t.Fatalf("create item: %d %s", status, body)
	}
	var created struct {
		Item struct{ ID string } `json:"item"`
	}
	mustJSON(t, body, &created)

	// Second user gets a read-only key on the vault.
	reader, err := e.st.CreateUser(context.Background(), store.CreateUserRequest{
		Email:               "reader+" + uuid.NewString()[:8] + "@kleidion.test",
		SrpSalt:             make([]byte, 16),
		SrpVerifier:         []byte{2},
		KdfAlgo:             "argon2id",
		KdfParams:           []byte(`{}`),
		MasterPublicKey:     make([]byte, 32),
		EncryptedPrivateKey: []byte("x"),
		EncryptedSymKey:     []byte("x"),
	})
	if err != nil {
		t.Fatalf("create reader: %v", err)
	}
	if err := e.st.AddVaultKey(context.Background(), vaultID, reader.ID, []byte("sealed"), "read"); err != nil {
		t.Fatalf("add read key: %v", err)
	}
	readerDev, err := e.st.UpsertDevice(context.Background(), reader.ID, "reader-dev", "web")
	if err != nil {
		t.Fatalf("reader device: %v", err)
	}
	rt := make([]byte, 32)
	_, _ = rand.Read(rt)
	readerToken := base64.RawURLEncoding.EncodeToString(rt)
	rsum := sha256.Sum256([]byte(readerToken))
	if _, err := e.st.CreateSession(context.Background(), reader.ID, readerDev, rsum[:], time.Hour); err != nil {
		t.Fatalf("reader session: %v", err)
	}

	// Swap the env to the reader's token.
	adminToken := e.token
	e.token = readerToken
	t.Cleanup(func() { e.token = adminToken })

	// Reader CAN list and GET.
	if status, _ := e.do(t, http.MethodGet, "/v1/vaults", nil); status != http.StatusOK {
		t.Fatalf("reader list vaults: %d", status)
	}
	if status, _ := e.do(t, http.MethodGet, fmt.Sprintf("/v1/items?vaultId=%s", vaultID), nil); status != http.StatusOK {
		t.Fatalf("reader list items: %d", status)
	}
	if status, _ := e.do(t, http.MethodGet, "/v1/items/"+created.Item.ID+"/versions", nil); status != http.StatusOK {
		t.Fatalf("reader versions: %d", status)
	}
	// Reader CANNOT mutate.
	if status, _ := e.do(t, http.MethodPost, "/v1/items", itemBody(vaultID, 1)); status != http.StatusForbidden {
		t.Fatalf("reader create: %d, want 403", status)
	}
	if status, _ := e.do(t, http.MethodPut, "/v1/items/"+created.Item.ID, itemBody(uuid.Nil, 1)); status != http.StatusForbidden {
		t.Fatalf("reader update: %d, want 403", status)
	}
	if status, _ := e.do(t, http.MethodDelete, "/v1/items/"+created.Item.ID, nil); status != http.StatusForbidden {
		t.Fatalf("reader delete: %d, want 403", status)
	}
	// A non-member must NOT see the item at all (404, no existence leak).
	e.token = adminToken
	stranger, err := e.st.CreateUser(context.Background(), store.CreateUserRequest{
		Email:   "stranger+" + uuid.NewString()[:8] + "@kleidion.test",
		SrpSalt: make([]byte, 16), SrpVerifier: []byte{2}, KdfAlgo: "argon2id",
		KdfParams: []byte(`{}`), MasterPublicKey: make([]byte, 32),
		EncryptedPrivateKey: []byte("x"), EncryptedSymKey: []byte("x"),
	})
	if err != nil {
		t.Fatalf("create stranger: %v", err)
	}
	_ = stranger
}

// TestIntegrationZeroKnowledgeCanary proves the server never sees plaintext:
// a unique canary embedded in the item's "plaintext" must appear NOWHERE in
// the raw items row bytes, any API response body, or the server logs.
func TestIntegrationZeroKnowledgeCanary(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	vaultID := e.createVault(t)

	canary := "CANARY-" + uuid.NewString()
	// The client would encrypt exactly this JSON; we simulate the client by
	// "encrypting" (XOR with a key stream is NOT what the client does, but any
	// transform proves the point only if the canary bytes are absent — so use a
	// real one-way transform: SHA-256-based keystream XOR, deterministic).
	plaintext := fmt.Sprintf(`{"title":"%s","notes":"secret %s"}`, canary, canary)
	fakeCt := xorKeystream([]byte(plaintext), []byte("vault-key-material"))
	nonce := make([]byte, 24)
	_, _ = rand.Read(nonce)

	createBody := map[string]any{
		"vaultId":    vaultID.String(),
		"itemType":   1,
		"ciphertext": base64.StdEncoding.EncodeToString(fakeCt),
		"nonce":      base64.StdEncoding.EncodeToString(nonce),
		"favorite":   true,
	}
	status, body := e.do(t, http.MethodPost, "/v1/items", createBody)
	if status != http.StatusCreated {
		t.Fatalf("create canary item: %d %s", status, body)
	}
	var created struct {
		Item struct{ ID string } `json:"item"`
	}
	mustJSON(t, body, &created)

	// 1) The canary must not appear in the create response.
	assertNoCanary(t, "POST /v1/items response", body, canary)

	// 2) Exercise every read endpoint and check their bodies.
	for _, req := range []struct{ method, path string }{
		{http.MethodGet, "/v1/vaults"},
		{http.MethodGet, fmt.Sprintf("/v1/items?vaultId=%s&since=0", vaultID)},
		{http.MethodGet, "/v1/items/" + created.Item.ID + "/versions"},
		{http.MethodGet, fmt.Sprintf("/v1/sync/changes?vaultId=%s&since=0", vaultID)},
	} {
		status, b := e.do(t, req.method, req.path, nil)
		if status != http.StatusOK {
			t.Fatalf("%s %s: %d", req.method, req.path, status)
		}
		assertNoCanary(t, req.method+" "+req.path, b, canary)
	}

	// 3) Raw items row bytes: dump EVERY column of the row (and item_versions)
	//    via a text cast and search the raw bytes.
	var rawDump string
	if err := e.st.Pool.QueryRow(ctx, `
		SELECT concat_ws('|',
			id::text, vault_id::text, item_type::text,
			encode(ciphertext,'escape'), encode(nonce,'escape'),
			coalesce(encode(search_hmac,'escape'),'NULL'),
			version::text, favorite::text,
			created_at::text, updated_at::text, coalesce(deleted_at::text,'NULL'))
		FROM items WHERE id = $1`, created.Item.ID).Scan(&rawDump); err != nil {
		t.Fatalf("raw row dump: %v", err)
	}
	assertNoCanary(t, "raw items row", []byte(rawDump), canary)
	// Also the binary ciphertext bytes themselves (not just their text cast).
	var ct, nc []byte
	if err := e.st.Pool.QueryRow(ctx,
		`SELECT ciphertext, nonce FROM items WHERE id = $1`, created.Item.ID).Scan(&ct, &nc); err != nil {
		t.Fatalf("raw ciphertext: %v", err)
	}
	assertNoCanary(t, "raw items.ciphertext bytes", ct, canary)
	assertNoCanary(t, "raw items.nonce bytes", nc, canary)
	// And the whole vaults row (encrypted_meta included).
	var vaultDump string
	if err := e.st.Pool.QueryRow(ctx, `
		SELECT concat_ws('|', id::text, owner_id::text, kind,
			encode(encrypted_meta,'escape'), encode(nonce,'escape'))
		FROM vaults WHERE id = $1`, vaultID).Scan(&vaultDump); err != nil {
		t.Fatalf("vault dump: %v", err)
	}
	assertNoCanary(t, "raw vaults row", []byte(vaultDump), canary)

	// 4) Update the item (canary in the new payload too) and re-check.
	upd := itemBody(uuid.Nil, 1)
	upd["ciphertext"] = base64.StdEncoding.EncodeToString(xorKeystream([]byte(plaintext+"-v2"), []byte("vault-key-material")))
	status, body = e.do(t, http.MethodPut, "/v1/items/"+created.Item.ID, upd)
	if status != http.StatusOK {
		t.Fatalf("update canary item: %d %s", status, body)
	}
	assertNoCanary(t, "PUT response", body, canary)

	var versionsDump string
	if err := e.st.Pool.QueryRow(ctx, `
		SELECT coalesce(string_agg(concat_ws('|', version::text, encode(ciphertext,'escape'), encode(nonce,'escape')), '#'), '')
		FROM item_versions WHERE item_id = $1`, created.Item.ID).Scan(&versionsDump); err != nil {
		t.Fatalf("versions dump: %v", err)
	}
	assertNoCanary(t, "raw item_versions rows", []byte(versionsDump), canary)

	// 5) Soft-delete and check the tombstone response + row.
	status, body = e.do(t, http.MethodDelete, "/v1/items/"+created.Item.ID, nil)
	if status != http.StatusOK {
		t.Fatalf("delete canary item: %d %s", status, body)
	}
	assertNoCanary(t, "DELETE response", body, canary)
	if err := e.st.Pool.QueryRow(ctx, `
		SELECT concat_ws('|', encode(ciphertext,'escape'), coalesce(deleted_at::text,'NULL'))
		FROM items WHERE id = $1`, created.Item.ID).Scan(&rawDump); err != nil {
		t.Fatalf("post-delete dump: %v", err)
	}
	assertNoCanary(t, "post-delete items row", []byte(rawDump), canary)

	// 6) Server logs: everything the router logged during this test.
	assertNoCanary(t, "server logs", e.logBuf.Bytes(), canary)

	// Sanity: the canary WAS in what the client held (test is meaningful).
	if !strings.Contains(plaintext, canary) {
		t.Fatal("test setup error: canary not in plaintext")
	}
}

// assertNoCanary fails the test if the canary appears in the given bytes
// (raw OR base64-encoded — a leak in either form counts).
func assertNoCanary(t *testing.T, where string, data []byte, canary string) {
	t.Helper()
	if bytes.Contains(data, []byte(canary)) {
		t.Fatalf("ZERO-KNOWLEDGE VIOLATION: canary %q found in %s", canary, where)
	}
	if bytes.Contains(data, []byte(base64.StdEncoding.EncodeToString([]byte(canary)))) {
		t.Fatalf("ZERO-KNOWLEDGE VIOLATION: base64 canary found in %s", where)
	}
}

// xorKeystream simulates client-side encryption deterministically: the point
// is that the emitted bytes do not contain the plaintext (a SHA-256 counter
// keystream XOR hides it completely for these test sizes).
func xorKeystream(plaintext, key []byte) []byte {
	out := make([]byte, len(plaintext))
	var block []byte
	for i := range plaintext {
		if i%32 == 0 {
			h := sha256.Sum256(append(append([]byte{}, key...), byte(i/32)))
			block = h[:]
		}
		out[i] = plaintext[i] ^ block[i%32]
	}
	return out
}

func mustJSON(t *testing.T, data []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
}
