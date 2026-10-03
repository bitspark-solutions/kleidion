package srp

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// goldenVector mirrors packages/crypto/test/vectors/srp-golden.json.
type goldenVector struct {
	Username        string `json:"username"`
	Salt            string `json:"salt"`
	X               string `json:"x"`
	Verifier        string `json:"verifier"`
	ClientEphemeral struct {
		Secret string `json:"secret"`
		Public string `json:"public"`
	} `json:"clientEphemeral"`
	ServerEphemeral struct {
		Secret string `json:"secret"`
		Public string `json:"public"`
	} `json:"serverEphemeral"`
	Session struct {
		Key           string `json:"key"`
		M1ClientProof string `json:"M1_clientProof"`
		M2ServerProof string `json:"M2_serverProof"`
	} `json:"session"`
}

// loadGolden reads the golden vector produced by the JS reference library.
// Path is relative to this test file: ../../../../packages/crypto/test/vectors/.
func loadGolden(t *testing.T) goldenVector {
	t.Helper()
	candidates := []string{
		filepath.Join("..", "..", "..", "..", "..", "packages", "crypto", "test", "vectors", "srp-golden.json"),
		filepath.Join("..", "..", "..", "..", "packages", "crypto", "test", "vectors", "srp-golden.json"),
		filepath.Join("packages", "crypto", "test", "vectors", "srp-golden.json"),
	}
	var raw []byte
	var err error
	for _, c := range candidates {
		raw, err = os.ReadFile(c)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("cannot read golden vector: %v", err)
	}
	var gv goldenVector
	if err := json.Unmarshal(raw, &gv); err != nil {
		t.Fatalf("cannot parse golden vector: %v", err)
	}
	return gv
}

func TestServerPublicEphemeralMatchesGolden(t *testing.T) {
	gv := loadGolden(t)
	b, err := ServerPublicEphemeral(gv.ServerEphemeral.Secret, gv.Verifier)
	if err != nil {
		t.Fatalf("ServerPublicEphemeral: %v", err)
	}
	want := gv.ServerEphemeral.Public
	if b != want {
		t.Errorf("B mismatch\n got: %s\nwant: %s", b, want)
	}
}

func TestDeriveServerSessionMatchesGolden(t *testing.T) {
	gv := loadGolden(t)
	sess, err := DeriveServerSession(
		gv.ServerEphemeral.Secret,
		gv.ClientEphemeral.Public,
		gv.Salt,
		gv.Username,
		gv.Verifier,
		gv.Session.M1ClientProof,
	)
	if err != nil {
		t.Fatalf("DeriveServerSession: %v", err)
	}

	if got := hex.EncodeToString(sess.Key); got != gv.Session.Key {
		t.Errorf("session key K mismatch\n got: %s\nwant: %s", got, gv.Session.Key)
	}
	if got := hex.EncodeToString(sess.ServerProof); got != gv.Session.M2ServerProof {
		t.Errorf("server proof M2 mismatch\n got: %s\nwant: %s", got, gv.Session.M2ServerProof)
	}
}

// TestBadClientProofRejected ensures a tampered M1 is refused.
func TestBadClientProofRejected(t *testing.T) {
	gv := loadGolden(t)
	// Flip a nibble in the client proof.
	bad := []byte(gv.Session.M1ClientProof)
	if bad[0] == '0' {
		bad[0] = '1'
	} else {
		bad[0] = '0'
	}
	_, err := DeriveServerSession(
		gv.ServerEphemeral.Secret,
		gv.ClientEphemeral.Public,
		gv.Salt,
		gv.Username,
		gv.Verifier,
		string(bad),
	)
	if err == nil {
		t.Fatal("expected error for tampered client proof, got nil")
	}
}

// TestZeroPublicRejected ensures A ≡ 0 mod N is refused (SRP-6a safety check).
func TestZeroPublicRejected(t *testing.T) {
	gv := loadGolden(t)
	_, err := DeriveServerSession(
		gv.ServerEphemeral.Secret,
		"00",
		gv.Salt,
		gv.Username,
		gv.Verifier,
		gv.Session.M1ClientProof,
	)
	if err == nil {
		t.Fatal("expected error for A=0, got nil")
	}
}
