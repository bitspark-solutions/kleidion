// Package auth implements account enrollment and SRP-6a sign-in.
//
// SECURITY INVARIANTS (ADR-005):
//   - The password and Secret Key never reach the server; the client derives
//     x (SRP private key) via 2SKD and sends only the verifier v = g^x.
//   - Unknown emails get a BOGUS challenge (random salt + verifier) so that
//     start/finish response shapes and timings do not reveal account existence.
//   - Challenges are single-use and expire in 5 minutes.
//   - Session tokens are 256-bit random; only their SHA-256 hash is stored.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kleidion/server/internal/auth/srp"
	"github.com/kleidion/server/internal/store"
)

// ChallengeTTL is how long an SRP challenge stays valid.
const ChallengeTTL = 5 * time.Minute

// SessionTTL is the default session lifetime.
const SessionTTL = 30 * 24 * time.Hour

// Service implements enrollment and sign-in against the store.
type Service struct {
	store *store.Store
}

// NewService wires the auth service.
func NewService(st *store.Store) *Service { return &Service{store: st} }

// KdfParams mirrors the client's Argon2id parameters.
type KdfParams struct {
	Algo     string `json:"algo"`
	OpsLimit int    `json:"opsLimit"`
	MemLimit int64  `json:"memLimit"`
}

// EnrollRequest is the client-computed enrollment material. The client has
// already: generated the Secret Key, derived x via 2SKD, computed v = g^x,
// generated its X25519 keypair, and wrapped its private key + sym key with AUK.
type EnrollRequest struct {
	Email               string    `json:"email"`
	SrpSalt             string    `json:"srpSalt"`     // hex, 16 bytes
	SrpVerifier         string    `json:"srpVerifier"` // hex
	Kdf                 KdfParams `json:"kdf"`
	MasterPublicKey     string    `json:"masterPublicKey"`     // hex, 32 bytes (X25519 pub)
	EncryptedPrivateKey string    `json:"encryptedPrivateKey"` // base64 (opaque AUK-wrapped blob)
	EncryptedSymKey     string    `json:"encryptedSymKey"`     // base64 (opaque)
}

// EnrollResponse returns the account id + the display fragment the client
// embeds in the Emergency Kit. NO secrets are returned.
type EnrollResponse struct {
	UserID    string `json:"userId"`
	Email     string `json:"email"`
	AccountID string `json:"accountId"` // 6-char fragment for the Secret Key display
}

// Enroll creates the account. Fails if the email exists or input is malformed.
func (s *Service) Enroll(ctx context.Context, req *EnrollRequest) (*EnrollResponse, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || !strings.Contains(email, "@") {
		return nil, fmt.Errorf("invalid email")
	}
	salt, err := hex.DecodeString(req.SrpSalt)
	if err != nil || len(salt) != 16 {
		return nil, fmt.Errorf("srpSalt must be 16 hex-decoded bytes")
	}
	verifier, err := hex.DecodeString(req.SrpVerifier)
	if err != nil || len(verifier) == 0 {
		return nil, fmt.Errorf("srpVerifier must be non-empty hex")
	}
	pub, err := hex.DecodeString(req.MasterPublicKey)
	if err != nil || len(pub) != 32 {
		return nil, fmt.Errorf("masterPublicKey must be 32 hex-decoded bytes (X25519)")
	}
	priv, err := base64.StdEncoding.DecodeString(req.EncryptedPrivateKey)
	if err != nil || len(priv) == 0 {
		return nil, fmt.Errorf("encryptedPrivateKey must be non-empty base64")
	}
	sym, err := base64.StdEncoding.DecodeString(req.EncryptedSymKey)
	if err != nil || len(sym) == 0 {
		return nil, fmt.Errorf("encryptedSymKey must be non-empty base64")
	}
	if req.Kdf.Algo != "argon2id" || req.Kdf.OpsLimit <= 0 || req.Kdf.MemLimit <= 0 {
		return nil, fmt.Errorf("kdf must be argon2id with positive opsLimit/memLimit")
	}
	kdfJSON, err := json.Marshal(req.Kdf)
	if err != nil {
		return nil, fmt.Errorf("kdf marshal: %w", err)
	}

	// Reject a weak verifier: it must be a valid group element (1 < v < N).
	if err := validateVerifier(req.SrpVerifier); err != nil {
		return nil, err
	}

	user, err := s.store.CreateUser(ctx, store.CreateUserRequest{
		Email:               email,
		SrpSalt:             salt,
		SrpVerifier:         verifier,
		KdfAlgo:             req.Kdf.Algo,
		KdfParams:           kdfJSON,
		MasterPublicKey:     pub,
		EncryptedPrivateKey: priv,
		EncryptedSymKey:     sym,
	})
	if err != nil {
		return nil, err
	}

	// Non-secret 6-char account fragment from the user id (for the Emergency Kit
	// display format KL-<ACCT>-...). Derived from the id, so stable per account.
	accountID := accountFragment(user.ID)
	return &EnrollResponse{UserID: user.ID.String(), Email: user.Email, AccountID: accountID}, nil
}

// validateVerifier ensures v is a plausible SRP verifier: hex, in (1, N).
func validateVerifier(verifierHex string) error {
	v, ok := new(big.Int).SetString(verifierHex, 16)
	if !ok {
		return errors.New("srpVerifier is not valid hex")
	}
	if v.Cmp(big.NewInt(1)) <= 0 || v.Cmp(srp.N) >= 0 {
		return errors.New("srpVerifier out of range (must satisfy 1 < v < N)")
	}
	return nil
}

// accountFragment derives a 6-char [A-Z0-9] fragment from a uuid (non-secret).
func accountFragment(id uuid.UUID) string {
	sum := sha256.Sum256(id[:])
	const alphabet = "ABCDEFGHJKMNPQRSTVWXYZ23456789" // unambiguous
	out := make([]byte, 6)
	for i := range out {
		out[i] = alphabet[int(sum[i])%len(alphabet)]
	}
	return string(out)
}

// SrpStartRequest begins sign-in.
type SrpStartRequest struct {
	Email         string `json:"email"`
	ClientPublicA string `json:"clientPublicA"` // hex, A = g^a
}

// SrpStartResponse returns the challenge + what the client needs to compute M1.
type SrpStartResponse struct {
	ChallengeID   string     `json:"challengeId"`
	SrpSalt       string     `json:"srpSalt"`       // hex — real for known users, random for unknown
	ServerPublicB string     `json:"serverPublicB"` // hex
	Kdf           KdfParams  `json:"kdf"`
	KeyBundle     *KeyBundle `json:"keyBundle"` // nil for unknown emails
}

// KeyBundle is the user's opaque encrypted key material, returned after the
// client proves knowledge (finish), not at start. Kept here for the finish
// response; start never returns it.
type KeyBundle struct {
	MasterPublicKey     string `json:"masterPublicKey"`
	EncryptedPrivateKey string `json:"encryptedPrivateKey"`
	EncryptedSymKey     string `json:"encryptedSymKey"`
}

// SrpStart performs step 1: look up the user (or fabricate a bogus challenge),
// generate b/B, store the challenge, return B + salt.
func (s *Service) SrpStart(ctx context.Context, req *SrpStartRequest) (*SrpStartResponse, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))
	A, err := hex.DecodeString(strings.TrimSpace(req.ClientPublicA))
	if err != nil || len(A) == 0 {
		return nil, fmt.Errorf("clientPublicA must be non-empty hex")
	}

	var (
		userID      *uuid.UUID
		salt        []byte
		verifierHex string
		kdf         KdfParams
	)

	user, err := s.store.GetUserByEmail(ctx, email)
	switch {
	case err == nil:
		uid := user.ID
		userID = &uid
		salt = user.SrpSalt
		verifierHex = hex.EncodeToString(user.SrpVerifier)
		if jerr := json.Unmarshal(user.KdfParams, &kdf); jerr != nil {
			return nil, fmt.Errorf("user kdf params corrupt: %w", jerr)
		}
	case errors.Is(err, store.ErrNotFound):
		// BOGUS challenge: random salt + random-but-valid verifier. The response
		// shape is identical to a real user's start, so account existence is not
		// revealed here. finish will fail proof verification (the client cannot
		// compute a valid M1 without the real x), which is indistinguishable
		// from a wrong password.
		salt = make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("bogus salt: %w", err)
		}
		bogusX := randomHex(32)
		v, err := srp.Verifier(bogusX)
		if err != nil {
			return nil, fmt.Errorf("bogus verifier: %w", err)
		}
		verifierHex = v
		kdf = KdfParams{Algo: "argon2id", OpsLimit: 3, MemLimit: 268435456}
	default:
		return nil, fmt.Errorf("user lookup: %w", err)
	}

	eph, err := srp.GenerateServerEphemeral(verifierHex)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral: %w", err)
	}

	chal, err := s.store.CreateSrpChallenge(ctx, userID, email,
		mustHexDecode(eph.Secret), mustHexDecode(eph.Public), A, salt, ChallengeTTL)
	if err != nil {
		return nil, fmt.Errorf("store challenge: %w", err)
	}

	return &SrpStartResponse{
		ChallengeID:   chal.ID.String(),
		SrpSalt:       hex.EncodeToString(salt),
		ServerPublicB: eph.Public,
		Kdf:           kdf,
	}, nil
}

// SrpFinishRequest completes sign-in.
type SrpFinishRequest struct {
	ChallengeID    string `json:"challengeId"`
	ClientProof    string `json:"clientProof"` // hex, M1
	DeviceName     string `json:"deviceName"`
	DevicePlatform string `json:"devicePlatform"`
}

// SrpFinishResponse returns the session token + server proof + (on success for
// a real user) the key bundle needed to unlock.
type SrpFinishResponse struct {
	SessionToken string     `json:"sessionToken"`
	ServerProof  string     `json:"serverProof"` // hex, M2 — client MUST verify
	UserID       string     `json:"userId"`
	Email        string     `json:"email"`
	KeyBundle    *KeyBundle `json:"keyBundle"`
}

// SrpFinish performs step 2: consume the challenge, verify M1, issue a session.
func (s *Service) SrpFinish(ctx context.Context, req *SrpFinishRequest) (*SrpFinishResponse, error) {
	chalID, err := uuid.Parse(req.ChallengeID)
	if err != nil {
		return nil, fmt.Errorf("invalid challengeId")
	}
	chal, err := s.store.ConsumeSrpChallenge(ctx, chalID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrInvalidChallenge
		}
		return nil, err
	}

	sess, err := srp.DeriveServerSession(
		hex.EncodeToString(chal.ServerSecret),
		hex.EncodeToString(chal.ClientPublic),
		hex.EncodeToString(chal.SrpSalt),
		chal.Email,
		// verifier: re-fetch from user for real accounts; for bogus challenges
		// userID is nil and we cannot verify — DeriveServerSession will fail the
		// proof, which is the desired outcome.
		s.verifierFor(ctx, chal),
		req.ClientProof,
	)
	if err != nil {
		// Uniform error for wrong password AND bogus challenge (no enumeration).
		return nil, ErrInvalidProof
	}

	// Only real accounts get a session; a bogus challenge cannot pass proof
	// verification, so reaching here implies chal.UserID != nil.
	if chal.UserID == nil {
		return nil, ErrInvalidProof
	}
	user, err := s.store.GetUserByID(ctx, *chal.UserID)
	if err != nil {
		return nil, fmt.Errorf("load user post-auth: %w", err)
	}
	if user.DisabledAt != nil {
		return nil, ErrAccountDisabled
	}

	token, tokenHash, err := newSessionToken()
	if err != nil {
		return nil, err
	}
	deviceID, err := s.store.UpsertDevice(ctx, *chal.UserID, orDefault(req.DeviceName, "unnamed device"), orDefault(req.DevicePlatform, "web"))
	if err != nil {
		return nil, fmt.Errorf("upsert device: %w", err)
	}
	if _, err := s.store.CreateSession(ctx, *chal.UserID, deviceID, tokenHash, SessionTTL); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	return &SrpFinishResponse{
		SessionToken: token,
		ServerProof:  hex.EncodeToString(sess.ServerProof),
		UserID:       user.ID.String(),
		Email:        user.Email,
		KeyBundle: &KeyBundle{
			MasterPublicKey:     hex.EncodeToString(user.MasterPublicKey),
			EncryptedPrivateKey: base64.StdEncoding.EncodeToString(user.EncryptedPrivateKey),
			EncryptedSymKey:     base64.StdEncoding.EncodeToString(user.EncryptedSymKey),
		},
	}, nil
}

// verifierFor returns the stored verifier hex for a real challenge, or a
// deterministic-but-wrong one for bogus challenges (proof will fail).
func (s *Service) verifierFor(ctx context.Context, chal *store.SrpChallenge) string {
	if chal.UserID == nil {
		return randomHex(32) // cannot match any client proof
	}
	u, err := s.store.GetUserByID(ctx, *chal.UserID)
	if err != nil {
		return randomHex(32)
	}
	return hex.EncodeToString(u.SrpVerifier)
}

// Errors returned by the service. Handlers map them to HTTP status codes.
var (
	ErrInvalidChallenge = errors.New("auth: challenge invalid, used, or expired")
	ErrInvalidProof     = errors.New("auth: client proof invalid")
	ErrAccountDisabled  = errors.New("auth: account disabled")
)

// newSessionToken returns (plaintextToken, sha256(token)). Only the hash is stored.
func newSessionToken() (string, []byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, fmt.Errorf("session token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(token))
	return token, sum[:], nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func mustHexDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("auth: internal hex decode failed: %v", err))
	}
	return b
}

func orDefault(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
