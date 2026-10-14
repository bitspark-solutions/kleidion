package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/kleidion/server/internal/auth"
	"github.com/kleidion/server/internal/store"
)

// TestLogoutRequiresSession verifies /logout is mounted behind session auth:
// requests with no or malformed Bearer headers get a uniform 401 and never
// reach the (nil) database.
func TestLogoutRequiresSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &authHandler{svc: auth.NewService(&store.Store{})}
	r := gin.New()
	r.POST("/v1/auth/logout", RequireSession(&store.Store{}), h.logout)

	cases := []struct {
		name   string
		header string
	}{
		{"no header", ""},
		{"wrong scheme", "Basic abc"},
		{"empty bearer", "Bearer "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", w.Code)
			}
		})
	}
}

// TestLogoutFailsClosedWithoutContext verifies the handler refuses to revoke
// (or claim success) when no session id was placed on the context — the stub
// that "returned ok" without doing anything is gone.
func TestLogoutFailsClosedWithoutContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &authHandler{svc: auth.NewService(&store.Store{})}
	r := gin.New()
	r.POST("/logout", h.logout) // deliberately NO RequireSession
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/logout", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (fail closed, no silent ok)", w.Code)
	}
}

// TestSessionRoutesRequireAuth covers GET /sessions + DELETE /sessions/:id
// behind RequireSession: anonymous callers get 401 before any DB access.
func TestSessionRoutesRequireAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	authed := r.Group("/v1", RequireSession(&store.Store{}))
	registerSessionRoutes(authed, auth.NewService(&store.Store{}), zerolog.Nop())

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/v1/sessions"},
		{http.MethodDelete, "/v1/sessions/6f9d0e6a-6a5b-4c3d-9e8f-0a1b2c3d4e5f"},
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s: status = %d, want 401", tc.method, tc.path, w.Code)
		}
	}
}

// TestSessionRoutesRejectAnonymousContextBadIDs verifies that with a session
// context present but a malformed :id, DELETE answers 400 without touching
// the store (parse must happen before any DB call).
func TestSessionDeleteRejectsMalformedID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &sessionHandler{svc: auth.NewService(&store.Store{})}
	r := gin.New()
	g := r.Group("", func(c *gin.Context) {
		c.Set(CtxUserID, uuid.New())
		c.Set(CtxSessionID, uuid.New())
		c.Next()
	})
	g.DELETE("/sessions/:id", h.revoke)

	// nil Pool store: reaching the DB would panic, so a clean 400 proves the
	// malformed id was rejected first.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/sessions/not-a-uuid", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for malformed session id", w.Code)
	}
}

// TestParseSessionIDParam checks the uuid guard helper directly.
func TestParseSessionIDParam(t *testing.T) {
	gin.SetMode(gin.TestMode)
	id := uuid.New()
	for _, tc := range []struct {
		name  string
		param string
		want  bool
	}{
		{"valid", id.String(), true},
		{"empty", "", false},
		{"garbage", "zzz", false},
		{"nil uuid", "00000000-0000-0000-0000-000000000000", false},
	} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Params = gin.Params{{Key: "id", Value: tc.param}}
		_, err := parseSessionIDParam(c)
		if (err == nil) != tc.want {
			t.Errorf("%s: err = %v, want ok = %v", tc.name, err, tc.want)
		}
	}
}

// TestSessionIDFromContext checks the context helper's fail-closed branches.
func TestSessionIDFromContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if _, err := sessionIDFromContext(c); err == nil {
		t.Error("missing session id must error")
	}
	c.Set(CtxSessionID, "not-a-uuid")
	if _, err := sessionIDFromContext(c); err == nil {
		t.Error("wrong-typed session id must error")
	}
	c.Set(CtxSessionID, uuid.Nil)
	if _, err := sessionIDFromContext(c); err == nil {
		t.Error("nil session id must error")
	}
	want := uuid.New()
	c.Set(CtxSessionID, want)
	got, err := sessionIDFromContext(c)
	if err != nil || got != want {
		t.Errorf("valid session id: got %v, err %v", got, err)
	}
}
