package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/kleidion/server/internal/config"
)

// newCORSTestRouter builds a router with a specific origin allow-list.
func newCORSTestRouter(t *testing.T, origins string) *httptest.Server {
	t.Helper()
	r := NewRouter(zerolog.Nop(), nil, config.Config{
		Env:            "development",
		Port:           "0",
		AllowedOrigins: origins,
	})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

// TestCORSPreflightSucceeds covers the bug that made the web UI unable to reach
// the API: an unhandled OPTIONS preflight returned 404 with no CORS headers, so
// the browser blocked every request ("Cannot reach the Kleidion server").
func TestCORSPreflightSucceeds(t *testing.T) {
	srv := newCORSTestRouter(t, "http://localhost:13000")

	req, err := http.NewRequest(http.MethodOptions, srv.URL+"/v1/auth/enroll", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Origin", "http://localhost:13000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "http://localhost:13000" {
		t.Errorf("Allow-Origin = %q, want http://localhost:13000", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Methods"); got == "" {
		t.Error("Allow-Methods missing")
	}
	if got := resp.Header.Get("Access-Control-Allow-Headers"); got == "" {
		t.Error("Allow-Headers missing")
	}
}

// TestCORSActualRequestCarriesHeader ensures real (non-preflight) calls get the
// header too, otherwise the browser still blocks reading the response.
func TestCORSActualRequestCarriesHeader(t *testing.T) {
	srv := newCORSTestRouter(t, "http://localhost:13000")

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/auth/srp/start", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Origin", "http://localhost:13000")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "http://localhost:13000" {
		t.Errorf("Allow-Origin = %q, want http://localhost:13000", got)
	}
	// Note: this router is built with a nil store, so auth routes are not
	// registered and the path 404s. The point of this test is that CORS runs as
	// middleware on EVERY response (including errors), which is what lets the
	// browser read error bodies from the UI. Handler-reaches-validation (400) is
	// covered by verify-stack.sh and the phase3 integration tests.
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (auth routes are unregistered with a nil store)", resp.StatusCode)
	}
	if got := resp.Header.Get("Vary"); got != "Origin" {
		t.Errorf("Vary = %q, want Origin (prevents cache poisoning across origins)", got)
	}
}

// TestCORSDisallowedOrigin asserts we do NOT reflect arbitrary origins — a
// wildcard or echoed Origin would let any site call the API with a stolen token.
func TestCORSDisallowedOrigin(t *testing.T) {
	srv := newCORSTestRouter(t, "http://localhost:13000")

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/auth/srp/start", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Origin", "https://evil.example.com")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin = %q, want empty for a disallowed origin", got)
	}
}

// TestCORSWildcardNeverEmitted guards the "no '*' with credentials" rule.
func TestCORSWildcardNeverEmitted(t *testing.T) {
	srv := newCORSTestRouter(t, "*") // even if someone misconfigures with a wildcard

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/auth/srp/start", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Origin", "http://localhost:13000")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got == "*" {
		t.Error("Allow-Origin must never be the literal wildcard")
	}
}

// TestCORSEmptyAllowListDenies verifies the safe default.
func TestCORSEmptyAllowListDenies(t *testing.T) {
	srv := newCORSTestRouter(t, "")

	req, err := http.NewRequest(http.MethodOptions, srv.URL+"/v1/auth/enroll", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Origin", "http://localhost:13000")
	req.Header.Set("Access-Control-Request-Method", "POST")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin = %q, want empty when allow-list is empty", got)
	}
	// Preflight still short-circuits (no route), just without CORS permission.
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
}

// TestCORSMultipleOrigins verifies comma-separated parsing and trailing-slash trim.
func TestCORSMultipleOrigins(t *testing.T) {
	srv := newCORSTestRouter(t, "http://localhost:13000, https://app.kleidion.com/")

	for _, origin := range []string{"http://localhost:13000", "https://app.kleidion.com"} {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/auth/srp/start", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Origin", origin)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		got := resp.Header.Get("Access-Control-Allow-Origin")
		resp.Body.Close()
		if got != origin {
			t.Errorf("origin %q: Allow-Origin = %q, want %q", origin, got, origin)
		}
	}
}
