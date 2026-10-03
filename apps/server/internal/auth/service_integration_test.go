package auth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/kleidion/server/internal/auth"
	"github.com/kleidion/server/internal/auth/srp"
	"github.com/kleidion/server/internal/store"
)

// testDBURL returns the Postgres URL for integration tests, or skips if unset.
//
// Run with:
//
//	KLEIDION_TEST_DATABASE_URL=postgres://kleidion:***@localhost:15432/kleidion_test?sslmode=disable \
//	  go test ./internal/auth/... -run Integration -v
func testDBURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("KLEIDION_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("KLEIDION_TEST_DATABASE_URL not set — skipping integration test")
	}
	return url
}

// newTestStore opens a store and runs migrations against a disposable database.
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, testDBURL(t), zerolog.Nop())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.MigrateWithRetry(ctx, 3, time.Second); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Wipe auth tables for isolation (test DB is disposable).
	for _, q := range []string{
		`TRUNCATE users, devices, sessions, srp_challenges RESTART IDENTITY CASCADE`,
	} {
		if _, err := st.Pool.Exec(ctx, q); err != nil {
			t.Fatalf("truncate: %v", err)
		}
	}
	return st
}

// clientX mimics what the TS client computes via 2SKD; for the integration
// test we use the standard SRP x derivation (the server only ever sees v).
func clientX(saltHex, username, password string) string {
	inner := sha256.Sum256([]byte(username + ":" + password))
	s, _ := hex.DecodeString(saltHex)
	out := sha256.Sum256(append(s, inner[:]...))
	return hex.EncodeToString(out[:])
}

// enrollTestUser signs up a user with client-computed material.
func enrollTestUser(t *testing.T, svc *auth.Service, email, password string) (*auth.EnrollResponse, string, string) {
	t.Helper()
	salt := "00112233445566778899aabbccddeeff"
	x := clientX(salt, email, password)
	v, err := srp.Verifier(x)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	// Fake X25519 keypair material (server treats it as opaque).
	pub := hex.EncodeToString(make([]byte, 32))
	blob := base64.StdEncoding.EncodeToString([]byte("opaque-a…-key"))
	resp, err := svc.Enroll(context.Background(), &auth.EnrollRequest{
		Email:               email,
		SrpSalt:             salt,
		SrpVerifier:         v,
		Kdf:                 auth.KdfParams{Algo: "argon2id", OpsLimit: 3, MemLimit: 268435456},
		MasterPublicKey:     pub,
		EncryptedPrivateKey: blob,
		EncryptedSymKey:     blob,
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	return resp, x, salt
}

// TestIntegrationEnrollAndSignin walks the full flow: enroll, then SRP sign-in.
func TestIntegrationEnrollAndSignin(t *testing.T) {
	st := newTestStore(t)
	svc := auth.NewService(st)
	ctx := context.Background()

	email := "alice+" + uuid.NewString()[:8] + "@kleidion.test"
	password := "correct horse battery staple"

	// --- Enroll ---
	_, x, salt := enrollTestUser(t, svc, email, password)

	// Enrolling the same email twice must conflict.
	_, err := svc.Enroll(ctx, &auth.EnrollRequest{
		Email: email, SrpSalt: salt, SrpVerifier: "02",
		Kdf:                 auth.KdfParams{Algo: "argon2id", OpsLimit: 3, MemLimit: 268435456},
		MasterPublicKey:     hex.EncodeToString(make([]byte, 32)),
		EncryptedPrivateKey: base64.StdEncoding.EncodeToString([]byte("x")),
		EncryptedSymKey:     base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if err == nil {
		t.Fatal("expected duplicate-email enroll to fail")
	}

	// --- SRP sign-in ---
	aSecret, aPublic, err := srp.GenerateClientEphemeral()
	if err != nil {
		t.Fatalf("client ephemeral: %v", err)
	}
	start, err := svc.SrpStart(ctx, &auth.SrpStartRequest{Email: email, ClientPublicA: aPublic})
	if err != nil {
		t.Fatalf("srp start: %v", err)
	}
	if start.KeyBundle != nil {
		t.Fatal("start must NOT return the key bundle")
	}
	if start.SrpSalt != salt {
		t.Fatalf("start returned salt %q, want %q", start.SrpSalt, salt)
	}

	// Client derives M1 using x (as the real client does via 2SKD).
	cs, err := srp.DeriveClientSession(aSecret, start.ServerPublicB, start.SrpSalt, email, x)
	if err != nil {
		t.Fatalf("client session: %v", err)
	}

	finish, err := svc.SrpFinish(ctx, &auth.SrpFinishRequest{
		ChallengeID:    start.ChallengeID,
		ClientProof:    hex.EncodeToString(cs.ClientProof),
		DeviceName:     "test-browser",
		DevicePlatform: "web",
	})
	if err != nil {
		t.Fatalf("srp finish: %v", err)
	}

	// Client MUST verify the server proof M2.
	if hex.EncodeToString(cs.ServerProof) != finish.ServerProof {
		t.Fatal("server proof M2 mismatch — client would reject this server")
	}
	if finish.SessionToken == "" {
		t.Fatal("expected a session token")
	}
	if finish.KeyBundle == nil || finish.KeyBundle.MasterPublicKey == "" {
		t.Fatal("expected key bundle on successful sign-in")
	}

	// The challenge is single-use: replaying finish must fail.
	if _, err := svc.SrpFinish(ctx, &auth.SrpFinishRequest{
		ChallengeID: start.ChallengeID, ClientProof: hex.EncodeToString(cs.ClientProof),
	}); err == nil {
		t.Fatal("expected challenge replay to fail")
	}
}

// TestIntegrationWrongPassword ensures a bad password fails uniformly.
func TestIntegrationWrongPassword(t *testing.T) {
	st := newTestStore(t)
	svc := auth.NewService(st)
	ctx := context.Background()

	email := "bob+" + uuid.NewString()[:8] + "@kleidion.test"
	_, _, salt := enrollTestUser(t, svc, email, "correct horse battery staple")

	aSecret, aPublic, err := srp.GenerateClientEphemeral()
	if err != nil {
		t.Fatalf("client ephemeral: %v", err)
	}
	start, err := svc.SrpStart(ctx, &auth.SrpStartRequest{Email: email, ClientPublicA: aPublic})
	if err != nil {
		t.Fatalf("srp start: %v", err)
	}

	// Client derives with the WRONG password → wrong x → wrong M1.
	wrongX := clientX(salt, email, "wrong password")
	cs, err := srp.DeriveClientSession(aSecret, start.ServerPublicB, start.SrpSalt, email, wrongX)
	if err != nil {
		t.Fatalf("client session: %v", err)
	}
	if _, err := svc.SrpFinish(ctx, &auth.SrpFinishRequest{
		ChallengeID: start.ChallengeID, ClientProof: hex.EncodeToString(cs.ClientProof),
	}); err != auth.ErrInvalidProof {
		t.Fatalf("expected ErrInvalidProof, got %v", err)
	}
}

// TestIntegrationUnknownAccountNoEnumeration ensures an unknown email yields a
// start response with the same SHAPE as a known account (bogus challenge), and
// finish fails with ErrInvalidProof (not a distinguishing error).
func TestIntegrationUnknownAccountNoEnumeration(t *testing.T) {
	st := newTestStore(t)
	svc := auth.NewService(st)
	ctx := context.Background()

	email := "nobody+" + uuid.NewString()[:8] + "@kleidion.test"
	aSecret, aPublic, err := srp.GenerateClientEphemeral()
	if err != nil {
		t.Fatalf("client ephemeral: %v", err)
	}
	start, err := svc.SrpStart(ctx, &auth.SrpStartRequest{Email: email, ClientPublicA: aPublic})
	if err != nil {
		t.Fatalf("srp start for unknown email must succeed (bogus challenge): %v", err)
	}
	// Shape check: same fields present as a real start.
	b, _ := json.Marshal(start)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for _, key := range []string{"challengeId", "srpSalt", "serverPublicB", "kdf"} {
		if _, ok := m[key]; !ok {
			t.Fatalf("bogus start missing key %q (enumeration risk): %v", key, m)
		}
	}
	if m["keyBundle"] != nil {
		t.Fatal("start must not leak a key bundle")
	}

	// Any M1 the client computes against the bogus verifier fails uniformly.
	cs, err := srp.DeriveClientSession(aSecret, start.ServerPublicB, start.SrpSalt, email, hex.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatalf("client session: %v", err)
	}
	if _, err := svc.SrpFinish(ctx, &auth.SrpFinishRequest{
		ChallengeID: start.ChallengeID, ClientProof: hex.EncodeToString(cs.ClientProof),
	}); err != auth.ErrInvalidProof {
		t.Fatalf("expected ErrInvalidProof for unknown account, got %v", err)
	}
}

// TestIntegrationValidation ensures malformed enroll requests are rejected.
func TestIntegrationValidation(t *testing.T) {
	st := newTestStore(t)
	svc := auth.NewService(st)
	ctx := context.Background()

	cases := []struct {
		name string
		req  auth.EnrollRequest
	}{
		{"empty email", auth.EnrollRequest{Email: "", SrpSalt: "00112233445566778899aabbccddeeff", SrpVerifier: "02"}},
		{"bad salt length", auth.EnrollRequest{Email: "x@y.z", SrpSalt: "0011", SrpVerifier: "02"}},
		{"non-hex salt", auth.EnrollRequest{Email: "x@y.z", SrpSalt: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", SrpVerifier: "02"}},
		{"bad kdf", auth.EnrollRequest{Email: "x@y.z", SrpSalt: "00112233445566778899aabbccddeeff", SrpVerifier: "02", Kdf: auth.KdfParams{Algo: "md5"}}},
		{"bad pubkey len", auth.EnrollRequest{Email: "x@y.z", SrpSalt: "00112233445566778899aabbccddeeff", SrpVerifier: "02", Kdf: auth.KdfParams{Algo: "argon2id", OpsLimit: 3, MemLimit: 67108864}, MasterPublicKey: "0011"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := svc.Enroll(ctx, &tc.req); err == nil {
				t.Fatal("expected validation error, got nil")
			}
		})
	}
}
