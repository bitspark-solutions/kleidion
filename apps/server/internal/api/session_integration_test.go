package api_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kleidion/server/internal/store"
)

// mintSession creates a second live session (own device + token) for the env
// user, bypassing SRP (the middleware only needs the token hash).
func mintSession(t *testing.T, e *testEnv, deviceName, platform, userAgent string) (sessionID uuid.UUID, token string) {
	t.Helper()
	deviceID, err := e.st.UpsertDevice(context.Background(), e.userID, deviceName, platform)
	if err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("token: %v", err)
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(token))
	id, err := e.st.CreateSession(context.Background(), e.userID, deviceID, sum[:], 24*time.Hour, userAgent)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return id, token
}

// mintOtherUserSession creates a SECOND user in the same test database with
// one live session, returning its user id, session id, and bearer token. Used
// to prove the session endpoints are strictly owner-scoped (each newTestEnv
// gets its own DB, so cross-user cases need an in-DB user).
func mintOtherUserSession(t *testing.T, e *testEnv) (userID, sessionID uuid.UUID, token string) {
	t.Helper()
	ctx := context.Background()
	u, err := e.st.CreateUser(ctx, store.CreateUserRequest{
		Email:               "other+" + uuid.NewString()[:8] + "@kleidion.test",
		SrpSalt:             make([]byte, 16),
		SrpVerifier:         []byte{2},
		KdfAlgo:             "argon2id",
		KdfParams:           []byte(`{"algo":"argon2id","opsLimit":3,"memLimit":268435456}`),
		MasterPublicKey:     make([]byte, 32),
		EncryptedPrivateKey: []byte("opaque"),
		EncryptedSymKey:     []byte("opaque"),
	})
	if err != nil {
		t.Fatalf("create other user: %v", err)
	}
	deviceID, err := e.st.UpsertDevice(ctx, u.ID, "other-device", "web")
	if err != nil {
		t.Fatalf("upsert other device: %v", err)
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("token: %v", err)
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(token))
	sessionID, err = e.st.CreateSession(ctx, u.ID, deviceID, sum[:], 24*time.Hour, "other-ua")
	if err != nil {
		t.Fatalf("create other session: %v", err)
	}
	return u.ID, sessionID, token
}

type sessionWire struct {
	ID             string `json:"id"`
	DeviceID       string `json:"deviceId"`
	DeviceName     string `json:"deviceName"`
	DevicePlatform string `json:"devicePlatform"`
	UserAgent      string `json:"userAgent"`
	CreatedAt      string `json:"createdAt"`
	LastUsedAt     string `json:"lastUsedAt"`
	ExpiresAt      string `json:"expiresAt"`
	Current        bool   `json:"current"`
}

func decodeSessions(t *testing.T, body []byte) []sessionWire {
	t.Helper()
	var resp struct {
		Sessions []sessionWire `json:"sessions"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode sessions: %v (body %s)", err, body)
	}
	return resp.Sessions
}

// TestIntegrationLogoutRevokesSession is the acceptance walk: a working token
// → POST /v1/auth/logout → the SAME token stops working immediately.
func TestIntegrationLogoutRevokesSession(t *testing.T) {
	e := newTestEnv(t)

	// Pre-state: the token authenticates.
	if status, body := e.do(t, http.MethodGet, "/v1/vaults", nil); status != http.StatusOK {
		t.Fatalf("vaults before logout: status %d body %s", status, body)
	}

	// Logout must answer 200 for a valid session.
	if status, body := e.do(t, http.MethodPost, "/v1/auth/logout", nil); status != http.StatusOK {
		t.Fatalf("logout: status %d body %s", status, body)
	}

	// The token is dead immediately: protected calls 401.
	if status, body := e.do(t, http.MethodGet, "/v1/vaults", nil); status != http.StatusUnauthorized {
		t.Fatalf("vaults after logout: status %d body %s, want 401", status, body)
	}

	// "Refresh after logout" — the revoked session cannot mint anything or be
	// re-used on any authed endpoint, including logout itself.
	if status, _ := e.do(t, http.MethodPost, "/v1/auth/logout", nil); status != http.StatusUnauthorized {
		t.Fatalf("second logout with dead token: status %d, want 401", status)
	}
	if status, _ := e.do(t, http.MethodGet, "/v1/sessions", nil); status != http.StatusUnauthorized {
		t.Fatalf("sessions list with dead token: status %d, want 401", status)
	}

	// Server-side truth: the row carries revoked_at.
	var revokedAt *time.Time
	if err := e.st.Pool.QueryRow(context.Background(),
		`SELECT revoked_at FROM sessions WHERE user_id = $1`, e.userID).Scan(&revokedAt); err != nil {
		t.Fatalf("read revoked_at: %v", err)
	}
	if revokedAt == nil {
		t.Fatal("logout did not set sessions.revoked_at")
	}
}

// TestIntegrationSessionsList shows device identity + UA + created/last-used
// metadata per session, scoped to the authenticated user, with the caller's
// own session marked current.
func TestIntegrationSessionsList(t *testing.T) {
	e := newTestEnv(t)

	otherID, _ := mintSession(t, e, "phone", "extension", "kleidion-ext/1.0")

	status, body := e.do(t, http.MethodGet, "/v1/sessions", nil)
	if status != http.StatusOK {
		t.Fatalf("sessions list: status %d body %s", status, body)
	}
	sessions := decodeSessions(t, body)
	if len(sessions) != 2 {
		t.Fatalf("want 2 sessions, got %d: %s", len(sessions), body)
	}

	var current, other *sessionWire
	nCurrent := 0
	for i := range sessions {
		s := &sessions[i]
		if s.Current {
			current = s
			nCurrent++
		} else {
			other = s
		}
	}
	if current == nil || other == nil || nCurrent != 1 {
		t.Fatalf("exactly one session must be marked current (got %d): %s", nCurrent, body)
	}
	if current.DeviceName != "test-device" || current.DevicePlatform != "web" {
		t.Errorf("current session device metadata wrong: %+v", current)
	}
	if current.UserAgent != "go-test" {
		t.Errorf("current session userAgent = %q, want %q", current.UserAgent, "go-test")
	}
	if current.CreatedAt == "" || current.LastUsedAt == "" || current.ExpiresAt == "" {
		t.Errorf("session timestamps missing: %+v", current)
	}
	if other.ID != otherID.String() || other.DeviceName != "phone" || other.DevicePlatform != "extension" {
		t.Errorf("second session wrong: %+v", other)
	}
}

// TestIntegrationSessionRevoke exercises DELETE /v1/sessions/:id: the target
// token dies, the caller's survives, unknown/malformed ids and other users'
// sessions never leak or die.
func TestIntegrationSessionRevoke(t *testing.T) {
	e := newTestEnv(t)

	targetID, targetToken := mintSession(t, e, "laptop", "desktop-windows", "Mozilla/Test")

	// The target token works before revocation.
	saved := e.token
	e.token = targetToken
	if status, _ := e.do(t, http.MethodGet, "/v1/vaults", nil); status != http.StatusOK {
		t.Fatalf("target token pre-revoke: status %d, want 200", status)
	}
	e.token = saved

	// Revoke it via the API as the owner.
	if status, body := e.do(t, http.MethodDelete, "/v1/sessions/"+targetID.String(), nil); status != http.StatusOK {
		t.Fatalf("revoke: status %d body %s", status, body)
	}

	// Target token is now dead; the caller's still lives.
	e.token = targetToken
	if status, _ := e.do(t, http.MethodGet, "/v1/vaults", nil); status != http.StatusUnauthorized {
		t.Fatalf("target token after revoke: status %d, want 401", status)
	}
	e.token = saved
	if status, _ := e.do(t, http.MethodGet, "/v1/vaults", nil); status != http.StatusOK {
		t.Fatalf("caller token after revoking another session: status %d, want 200", status)
	}

	// Revoking twice or revoking an unknown id is a uniform 404.
	if status, _ := e.do(t, http.MethodDelete, "/v1/sessions/"+targetID.String(), nil); status != http.StatusNotFound {
		t.Fatalf("double revoke: status %d, want 404", status)
	}
	if status, _ := e.do(t, http.MethodDelete, "/v1/sessions/"+uuid.NewString(), nil); status != http.StatusNotFound {
		t.Fatalf("unknown id: status %d, want 404", status)
	}

	// Cross-user isolation: another user's session id (SAME database) answers
	// a uniform 404 and that user's session stays alive.
	_, otherSessID, otherToken := mintOtherUserSession(t, e)
	if status, _ := e.do(t, http.MethodDelete, "/v1/sessions/"+otherSessID.String(), nil); status != http.StatusNotFound {
		t.Fatalf("cross-user revoke: status %d, want 404", status)
	}
	old := e.token
	e.token = otherToken
	if status, _ := e.do(t, http.MethodGet, "/v1/vaults", nil); status != http.StatusOK {
		t.Fatalf("other user's token after cross-user revoke attempt: status %d, want 200", status)
	}
	e.token = old
}

// TestIntegrationLastUsedTouch verifies authenticated requests bump
// last_used_at (stale rows are refreshed; the middleware is the writer).
func TestIntegrationLastUsedTouch(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()

	var before time.Time
	if err := e.st.Pool.QueryRow(ctx,
		`SELECT last_used_at FROM sessions WHERE user_id = $1`, e.userID).Scan(&before); err != nil {
		t.Fatalf("read last_used_at: %v", err)
	}

	// Force the row stale, then make an authenticated call.
	if _, err := e.st.Pool.Exec(ctx,
		`UPDATE sessions SET last_used_at = now() - interval '2 hours' WHERE user_id = $1`, e.userID); err != nil {
		t.Fatalf("stale: %v", err)
	}
	if status, _ := e.do(t, http.MethodGet, "/v1/vaults", nil); status != http.StatusOK {
		t.Fatalf("vaults: status %d", status)
	}

	var after time.Time
	if err := e.st.Pool.QueryRow(ctx,
		`SELECT last_used_at FROM sessions WHERE user_id = $1`, e.userID).Scan(&after); err != nil {
		t.Fatalf("read after: %v", err)
	}
	if !after.After(before) {
		t.Fatalf("last_used_at not touched: before %v after %v", before, after)
	}
	if d := time.Since(after); d > 5*time.Minute {
		t.Fatalf("touched value not fresh: %v ago", d)
	}
}

// TestIntegrationSessionsScopedToUser ensures the list only ever contains the
// caller's own sessions, even when another user has a live session in the
// same database.
func TestIntegrationSessionsScopedToUser(t *testing.T) {
	e := newTestEnv(t)
	otherUserID, otherSessionID, _ := mintOtherUserSession(t, e)
	_, _, _ = mintOtherUserSession(t, e) // a third, for good measure

	status, body := e.do(t, http.MethodGet, "/v1/sessions", nil)
	if status != http.StatusOK {
		t.Fatalf("sessions: status %d body %s", status, body)
	}
	sessions := decodeSessions(t, body)
	if len(sessions) != 1 {
		t.Fatalf("want only the caller's 1 session, got %d: %s", len(sessions), body)
	}
	if sessions[0].ID == otherSessionID.String() || !sessions[0].Current {
		t.Fatalf("listed session is not the caller's current one: %+v", sessions[0])
	}

	var owner uuid.UUID
	if err := e.st.Pool.QueryRow(context.Background(),
		`SELECT user_id FROM sessions WHERE id = $1`, sessions[0].ID).Scan(&owner); err != nil {
		t.Fatalf("owner lookup: %v", err)
	}
	if owner != e.userID || owner == otherUserID {
		t.Fatalf("listed session belongs to %s, caller is %s", owner, e.userID)
	}
}
