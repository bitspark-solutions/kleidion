package api_test

// Live-stack end-to-end proof for real logout. Unlike the httptest suites,
// this walks the FULL SRP sign-in over HTTP against a running server —
// enroll → srp/start → srp/finish (real M1/M2) → protected call → sessions
// list → logout → the token must be dead immediately.
//
// Run against a live stack:
//
//	KLEIDION_LIVE_API_URL=http://localhost:18080 go test ./internal/api/ -run TestLiveLogout -v

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kleidion/server/internal/auth/srp"
)

func TestLiveLogoutEndToEnd(t *testing.T) {
	base := strings.TrimRight(os.Getenv("KLEIDION_LIVE_API_URL"), "/")
	if base == "" {
		t.Skip("KLEIDION_LIVE_API_URL not set — skipping live-stack test")
	}
	client := &http.Client{Timeout: 15 * time.Second}

	// --- helpers ---
	post := func(path string, body any, token string) (int, []byte) {
		t.Helper()
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(b))
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, raw
	}
	get := func(path, token string) (int, []byte) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, raw
	}

	// --- 1. enroll a throwaway account (client-side material; server sees
	// only verifier + opaque blobs) ---
	email := "live+" + strings.ReplaceAll(uuid.NewString()[:8], "-", "") + "@kleidion.test"
	password := "correct horse battery staple"
	saltBytes := make([]byte, 16)
	if _, err := rand.Read(saltBytes); err != nil {
		t.Fatalf("salt: %v", err)
	}
	saltHex := hex.EncodeToString(saltBytes)
	inner := sha256.Sum256([]byte(email + ":" + password))
	outer := sha256.Sum256(append(saltBytes, inner[:]...))
	xHex := hex.EncodeToString(outer[:])
	vHex, err := srp.Verifier(xHex)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	opaque := base64.StdEncoding.EncodeToString([]byte("opaque-key-material"))
	status, body := post("/v1/auth/enroll", map[string]any{
		"email":               email,
		"srpSalt":             saltHex,
		"srpVerifier":         vHex,
		"kdf":                 map[string]any{"algo": "argon2id", "opsLimit": 3, "memLimit": 268435456},
		"masterPublicKey":     hex.EncodeToString(make([]byte, 32)),
		"encryptedPrivateKey": opaque,
		"encryptedSymKey":     opaque,
	}, "")
	if status != http.StatusCreated {
		t.Fatalf("enroll: status %d body %s", status, body)
	}

	// --- 2. full SRP sign-in ---
	aSecret, aPublic, err := srp.GenerateClientEphemeral()
	if err != nil {
		t.Fatalf("ephemeral: %v", err)
	}
	status, body = post("/v1/auth/srp/start", map[string]string{"email": email, "clientPublicA": aPublic}, "")
	if status != http.StatusOK {
		t.Fatalf("srp start: status %d body %s", status, body)
	}
	var start struct {
		ChallengeID   string `json:"challengeId"`
		SrpSalt       string `json:"srpSalt"`
		ServerPublicB string `json:"serverPublicB"`
	}
	if err := json.Unmarshal(body, &start); err != nil {
		t.Fatalf("decode start: %v", err)
	}
	cs, err := srp.DeriveClientSession(aSecret, start.ServerPublicB, start.SrpSalt, email, xHex)
	if err != nil {
		t.Fatalf("client session: %v", err)
	}
	status, body = post("/v1/auth/srp/finish", map[string]string{
		"challengeId":    start.ChallengeID,
		"clientProof":    hex.EncodeToString(cs.ClientProof),
		"deviceName":     "live-e2e",
		"devicePlatform": "cli",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("srp finish: status %d body %s", status, body)
	}
	var finish struct {
		SessionToken string `json:"sessionToken"`
	}
	if err := json.Unmarshal(body, &finish); err != nil {
		t.Fatalf("decode finish: %v", err)
	}
	if finish.SessionToken == "" {
		t.Fatal("no session token from live server")
	}
	token := finish.SessionToken

	// --- 3. protected call works ---
	if status, body := get("/v1/vaults", token); status != http.StatusOK {
		t.Fatalf("vaults with fresh token: status %d body %s", status, body)
	}

	// --- 4. sessions list shows this live session ---
	status, body = get("/v1/sessions", token)
	if status != http.StatusOK {
		t.Fatalf("sessions list: status %d body %s", status, body)
	}
	var list struct {
		Sessions []sessionWire `json:"sessions"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decode sessions: %v", err)
	}
	var current *sessionWire
	for i := range list.Sessions {
		if list.Sessions[i].Current {
			current = &list.Sessions[i]
		}
	}
	if current == nil {
		t.Fatalf("live session not listed / not marked current: %s", body)
	}
	if current.DeviceName != "live-e2e" {
		t.Errorf("deviceName = %q, want live-e2e", current.DeviceName)
	}
	// UA is captured server-side from the header (Go's default client UA).
	if !strings.Contains(current.UserAgent, "Go-http-client") {
		t.Errorf("userAgent = %q, want the request's User-Agent", current.UserAgent)
	}
	if current.CreatedAt == "" || current.LastUsedAt == "" || current.ExpiresAt == "" {
		t.Errorf("metadata timestamps missing: %+v", current)
	}

	// --- 5. LOGOUT — and the token dies immediately ---
	if status, body := post("/v1/auth/logout", map[string]any{}, token); status != http.StatusOK {
		t.Fatalf("logout: status %d body %s", status, body)
	}
	if status, body := get("/v1/vaults", token); status != http.StatusUnauthorized {
		t.Fatalf("SECURITY: vaults after logout: status %d body %s, want 401", status, body)
	}
	// Any further "refresh" with the dead token fails.
	if status, _ := get("/v1/sessions", token); status != http.StatusUnauthorized {
		t.Fatalf("sessions after logout: status %d, want 401", status)
	}
	if status, _ := post("/v1/auth/logout", map[string]any{}, token); status != http.StatusUnauthorized {
		t.Fatalf("logout replay after logout: status %d, want 401", status)
	}
}
