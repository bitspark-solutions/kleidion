package srp

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
)

// EphemeralBytes is the size of the server's secret ephemeral b (256 bits).
const EphemeralBytes = 32

// ServerEphemeral holds the server's secret/public ephemeral pair (b, B).
type ServerEphemeral struct {
	// Secret is b (hex, 32 bytes). NEVER returned to the client.
	Secret string
	// Public is B = (k*v + g^b) mod N (hex, padded to N-length). Returned at start.
	Public string
}

// GenerateServerEphemeral produces (b, B) for a verifier v (hex). This mirrors
// the JS `srp.generateEphemeral(verifier)`. The secret b must be persisted
// (srp_challenges) and used exactly once in DeriveServerSession.
func GenerateServerEphemeral(verifierHex string) (*ServerEphemeral, error) {
	v, ok := new(big.Int).SetString(verifierHex, 16)
	if !ok {
		return nil, errBadInput
	}
	bBuf := make([]byte, EphemeralBytes)
	if _, err := rand.Read(bBuf); err != nil {
		return nil, err
	}
	b := new(big.Int).SetBytes(bBuf)
	bHex := hex.EncodeToString(padN(b))

	// B = (k*v + g^b) mod N
	B := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(K, v), modPow(G, b, N)), N)
	return &ServerEphemeral{Secret: bHex, Public: hex.EncodeToString(padN(B))}, nil
}

// ClientPublicFromEphemeral recomputes A = g^a mod N from a client secret a
// (hex). Used only in tests to build vectors; clients normally send A directly.
func ClientPublicFromEphemeral(clientSecretEphemeral string) (string, error) {
	a, ok := new(big.Int).SetString(clientSecretEphemeral, 16)
	if !ok {
		return "", errBadInput
	}
	A := modPow(G, a, N)
	return hex.EncodeToString(padN(A)), nil
}

// Verifier computes v = g^x mod N from a private key x (hex). Used at enroll
// time; x is derived on the client via 2SKD and never sent to the server — the
// client sends only v. Kept server-side for tests and admin tooling.
func Verifier(privateKeyHex string) (string, error) {
	x, ok := new(big.Int).SetString(privateKeyHex, 16)
	if !ok {
		return "", errBadInput
	}
	v := modPow(G, x, N)
	return hex.EncodeToString(padN(v)), nil
}
