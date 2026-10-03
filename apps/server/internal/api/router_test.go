package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/kleidion/server/internal/config"
)

// newTestRouter builds a router with a nil store (routes under test must not
// touch the database).
func newTestRouter(t *testing.T) *httptest.Server {
	t.Helper()
	log := zerolog.Nop()
	r := NewRouter(log, nil, config.Config{Env: "development", Port: "0"})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func TestHealthz(t *testing.T) {
	srv := newTestRouter(t)
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("body = %v, want status ok", body)
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}
}

func TestV1Status(t *testing.T) {
	srv := newTestRouter(t)
	resp, err := http.Get(srv.URL + "/v1/status")
	if err != nil {
		t.Fatalf("GET /v1/status: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	// /v1/status returns mixed value types ("auth" is an object), so decode into
	// map[string]any rather than map[string]string.
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["api"] != "v1" {
		t.Fatalf("body = %v, want api v1", body)
	}
	authInfo, ok := body["auth"].(map[string]any)
	if !ok {
		t.Fatalf("body.auth = %v (%T), want object", body["auth"], body["auth"])
	}
	if authInfo["srp"] != true {
		t.Fatalf("body.auth = %v, want srp true", authInfo)
	}
}
