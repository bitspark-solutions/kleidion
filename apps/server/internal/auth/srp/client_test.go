package srp

import (
	"encoding/hex"
	"testing"
)

// TestClientSessionMatchesGolden proves the Go CLIENT derivation reproduces the
// JS reference's K/M1/M2 — the same golden vector the TS client passes.
func TestClientSessionMatchesGolden(t *testing.T) {
	gv := loadGolden(t)
	sess, err := DeriveClientSession(
		gv.ClientEphemeral.Secret,
		gv.ServerEphemeral.Public,
		gv.Salt,
		gv.Username,
		gv.X,
	)
	if err != nil {
		t.Fatalf("DeriveClientSession: %v", err)
	}
	if got := hex.EncodeToString(sess.Key); got != gv.Session.Key {
		t.Errorf("client K mismatch\n got: %s\nwant: %s", got, gv.Session.Key)
	}
	if got := hex.EncodeToString(sess.ClientProof); got != gv.Session.M1ClientProof {
		t.Errorf("client M1 mismatch\n got: %s\nwant: %s", got, gv.Session.M1ClientProof)
	}
	if got := hex.EncodeToString(sess.ServerProof); got != gv.Session.M2ServerProof {
		t.Errorf("client-expected M2 mismatch\n got: %s\nwant: %s", got, gv.Session.M2ServerProof)
	}
}

// TestFullHandshakeGoToGo runs a complete client+server handshake in Go using
// the standard x derivation, proving the two sides interoperate end-to-end.
func TestFullHandshakeGoToGo(t *testing.T) {
	username := "bob@kleidion.com"
	salt := "00112233445566778899aabbccddeeff"
	// x derived from a password (standard SRP derivation, for this test).
	x := deriveXForTest(salt, username, "correct horse battery staple")
	v, err := Verifier(x)
	if err != nil {
		t.Fatalf("Verifier: %v", err)
	}

	// Client: generate a, A
	aSecret, aPublic, err := GenerateClientEphemeral()
	if err != nil {
		t.Fatalf("client ephemeral: %v", err)
	}

	// Server: start (generate b, B)
	eph, err := GenerateServerEphemeral(v)
	if err != nil {
		t.Fatalf("server ephemeral: %v", err)
	}

	// Client: derive session, produce M1
	cs, err := DeriveClientSession(aSecret, eph.Public, salt, username, x)
	if err != nil {
		t.Fatalf("client session: %v", err)
	}

	// Server: verify M1, produce M2
	ss, err := DeriveServerSession(eph.Secret, aPublic, salt, username, v, hex.EncodeToString(cs.ClientProof))
	if err != nil {
		t.Fatalf("server session: %v", err)
	}

	// Both sides must derive the same K
	if hex.EncodeToString(cs.Key) != hex.EncodeToString(ss.Key) {
		t.Fatal("client and server session keys differ")
	}
	// Client verifies M2 matches what it expected
	if hex.EncodeToString(cs.ServerProof) != hex.EncodeToString(ss.ServerProof) {
		t.Fatal("server proof M2 mismatch")
	}
}

// deriveXForTest mirrors the standard SRP x = H(s | H(I|":"|p)) for tests only.
func deriveXForTest(saltHex, username, password string) string {
	inner := sha256Bytes([]byte(username + ":" + password))
	s, _ := hex.DecodeString(saltHex)
	return hex.EncodeToString(sha256Bytes(s, inner))
}
