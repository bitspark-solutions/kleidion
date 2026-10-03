package srp

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
)

// ClientSession is the result of the client-side SRP derivation.
type ClientSession struct {
	// Key is the shared session key K = H(S).
	Key []byte
	// ClientProof is M1 = H(H(N)^H(g)|H(I)|s|A|B|K), sent to the server.
	ClientProof []byte
	// ServerProof is the M2 the client expects back (for verification).
	ServerProof []byte
}

// GenerateClientEphemeral produces (a, A=g^a mod N) as padded hex.
func GenerateClientEphemeral() (secret string, public string, err error) {
	aBuf := make([]byte, EphemeralBytes)
	if _, err := rand.Read(aBuf); err != nil {
		return "", "", err
	}
	a := new(big.Int).SetBytes(aBuf)
	A := modPow(G, a, N)
	return hex.EncodeToString(padN(a)), hex.EncodeToString(padN(A)), nil
}

// DeriveClientSession computes the client session key and proofs. This is the
// exact mirror of packages/crypto/src/srp/client.ts:deriveClientSession and is
// validated against the same golden vector.
//
// Inputs are hex: clientSecretEphemeral a, serverPublicEphemeral B, salt s,
// privateKey x (from 2SKD in production). username feeds H(I) in M1.
func DeriveClientSession(clientSecretEphemeral, serverPublicEphemeral, saltHex, username, privateKeyHex string) (*ClientSession, error) {
	a, ok := new(big.Int).SetString(clientSecretEphemeral, 16)
	if !ok {
		return nil, errBadInput
	}
	B, ok := new(big.Int).SetString(serverPublicEphemeral, 16)
	if !ok {
		return nil, errBadInput
	}
	x, ok := new(big.Int).SetString(privateKeyHex, 16)
	if !ok {
		return nil, errBadInput
	}

	// B % N must not be zero (guards against a malicious server).
	if new(big.Int).Mod(B, N).Sign() == 0 {
		return nil, errInvalidPublic
	}

	A := modPow(G, a, N)
	aHex := hex.EncodeToString(padN(A))
	bHex := hex.EncodeToString(padN(B))

	u, err := computeU(aHex, bHex)
	if err != nil {
		return nil, err
	}

	// S = (B - k*g^x)^(a + u*x) mod N
	kgx := new(big.Int).Mod(new(big.Int).Mul(K, modPow(G, x, N)), N)
	diff := new(big.Int).Sub(B, kgx)
	diff.Mod(diff, N) // Go's Mod returns a non-negative result for positive modulus
	exp := new(big.Int).Add(a, new(big.Int).Mul(u, x))
	S := modPow(diff, exp, N)

	key := sha256Bytes(padN(S))
	keyHex := hex.EncodeToString(key)

	m1, err := computeM1(aHex, bHex, keyHex, username, saltHex)
	if err != nil {
		return nil, err
	}
	m2, err := computeM2(aHex, m1, key)
	if err != nil {
		return nil, err
	}
	return &ClientSession{Key: key, ClientProof: m1, ServerProof: m2}, nil
}
