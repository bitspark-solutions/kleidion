package api

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/kleidion/server/internal/store"
)

// TestDecodeB64Field covers the contract's binary-field decoding rules:
// non-empty base64, exact lengths where specified, optional fields.
func TestDecodeB64Field(t *testing.T) {
	b24 := base64.StdEncoding.EncodeToString(make([]byte, 24))
	b32 := base64.StdEncoding.EncodeToString(make([]byte, 32))

	if _, err := decodeB64Field("", "nonce", false, nonceLen); err == nil {
		t.Error("empty required field must fail")
	}
	if b, err := decodeB64Field("", "searchHmac", true, searchHmacLen); err != nil || b != nil {
		t.Errorf("empty optional field must succeed with nil, got %v %v", b, err)
	}
	if _, err := decodeB64Field("not base64!!", "ciphertext", false, 0); err == nil {
		t.Error("non-base64 must fail")
	}
	if _, err := decodeB64Field(b24, "nonce", false, nonceLen); err != nil {
		t.Errorf("valid 24-byte nonce must pass: %v", err)
	}
	if _, err := decodeB64Field(b32, "nonce", false, nonceLen); err == nil {
		t.Error("32-byte nonce must fail the 24-byte check")
	}
	if _, err := decodeB64Field(b24, "searchHmac", false, searchHmacLen); err == nil {
		t.Error("24-byte searchHmac must fail the 32-byte check")
	}
	// base64 of an empty string decodes to zero bytes → still invalid.
	if _, err := decodeB64Field("", "ciphertext", false, 0); err == nil {
		t.Error("empty ciphertext must fail")
	}
}

// TestItemPayloadValidation covers itemType 1..4 and the 1 MiB cap.
func TestItemPayloadValidation(t *testing.T) {
	ct := base64.StdEncoding.EncodeToString([]byte("opaque"))
	nonce := base64.StdEncoding.EncodeToString(make([]byte, 24))
	hmac := base64.StdEncoding.EncodeToString(make([]byte, 32))

	var p itemPayload
	if err := p.validate(ct, nonce, hmac, 1); err != nil {
		t.Fatalf("valid payload must pass: %v", err)
	}
	if err := p.validate(ct, nonce, "", 4); err != nil {
		t.Fatalf("valid payload without hmac must pass: %v", err)
	}
	for _, badType := range []int{0, 5, -1} {
		if err := p.validate(ct, nonce, "", badType); err == nil {
			t.Errorf("itemType %d must fail", badType)
		}
	}
	if err := p.validate("", nonce, "", 1); err == nil {
		t.Error("empty ciphertext must fail")
	}
	if err := p.validate(ct, base64.StdEncoding.EncodeToString(make([]byte, 12)), "", 1); err == nil {
		t.Error("12-byte nonce must fail")
	}
	if err := p.validate(ct, nonce, base64.StdEncoding.EncodeToString(make([]byte, 31)), 1); err == nil {
		t.Error("31-byte searchHmac must fail")
	}
	// 1 MiB + 1 byte ciphertext must be rejected.
	big := base64.StdEncoding.EncodeToString(make([]byte, maxCiphertextLen+1))
	if err := p.validate(big, nonce, "", 1); !strings.Contains(errString(err), "1 MiB") {
		t.Errorf("oversized ciphertext must fail with 1 MiB message, got %v", err)
	}
	// Exactly 1 MiB is allowed.
	exact := base64.StdEncoding.EncodeToString(make([]byte, maxCiphertextLen))
	if err := p.validate(exact, nonce, "", 1); err != nil {
		t.Errorf("exactly 1 MiB must pass: %v", err)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// TestParseSince covers the delta cursor parsing.
func TestParseSince(t *testing.T) {
	if n, err := parseSince(""); err != nil || n != 0 {
		t.Errorf("absent since must be 0, got %d %v", n, err)
	}
	if n, err := parseSince("42"); err != nil || n != 42 {
		t.Errorf("since=42, got %d %v", n, err)
	}
	for _, bad := range []string{"abc", "-1", "1.5"} {
		if _, err := parseSince(bad); err == nil {
			t.Errorf("since=%q must fail", bad)
		}
	}
}

// TestParseVaultIDParam rejects non-uuid vaultIds (contract: 400).
func TestParseVaultIDParam(t *testing.T) {
	if _, err := parseVaultIDParam("not-a-uuid"); err == nil {
		t.Error("non-uuid must fail")
	}
	if _, err := parseVaultIDParam("6f9d0e6a-6a5b-4c3d-9e8f-0a1b2c3d4e5f"); err != nil {
		t.Errorf("valid uuid must pass: %v", err)
	}
}

// TestRequireSessionRejects verifies the middleware returns a uniform 401
// when no store is configured or no/bad Bearer header is supplied, without
// ever touching the database.
func TestRequireSessionRejects(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name   string
		st     *store.Store
		header string
	}{
		{"nil store", nil, "Bearer ***"},
		{"no header", &store.Store{}, ""},
		{"wrong scheme", &store.Store{}, "Basic abc"},
		{"empty bearer", &store.Store{}, "Bearer "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			g := r.Group("/v1", RequireSession(tc.st))
			g.GET("/vaults", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{}) })

			req := httptest.NewRequest(http.MethodGet, "/v1/vaults", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", w.Code)
			}
			if !strings.Contains(w.Body.String(), `"error"`) {
				t.Fatalf("body = %s, want {\"error\":...}", w.Body.String())
			}
		})
	}
}
