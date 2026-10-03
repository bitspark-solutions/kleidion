// Package srp implements SRP-6a (RFC 5054) exactly matching the JS reference
// (secure-remote-password@0.3.1) used by the Kleidion web/extension/mobile
// clients.
//
// INTEROP CONTRACT — the Go server and the TS client MUST agree byte-for-byte.
// Both sides are validated against packages/crypto/test/vectors/srp-golden.json.
//
// Fixed parameters:
//   - Group: RFC 5054 2048-bit, g = 2
//   - Hash: SHA-256
//   - k = H(N | g), where g hashes as the SINGLE byte 0x02 (NOT padded)
//   - A, B, S padded to N's byte-length (256) before hashing
//   - M1 = H( H(N)^H(g) | H(I) | s | A | B | K )   [RFC 2945/5054 proof form]
//   - M2 = H( A | M1 | K )
//   - K  = H(S)
package srp

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"math/big"
)

// N_HEX is the RFC 5054 2048-bit group modulus.
const nHex = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC319294" +
	"3DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310D" +
	"CD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FB" +
	"D5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF74" +
	"7359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A" +
	"436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D" +
	"5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E73" +
	"03CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
	"94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F" +
	"9E4AFF73"

var (
	// N is the group modulus.
	N = mustHexBig(nHex)
	// G is the generator (2).
	G = big.NewInt(2)
	// nBytes is the padded byte-length of N (256).
	nBytes = len(nHex) / 2
	// K is the multiplier k = H(N | g), g hashed as the single byte 0x02.
	K = multiplier()
	// hnXorHg is H(N) XOR H(g), the fixed prefix of proof M1.
	hnXorHg = hnXorHgConst()
)

func mustHexBig(h string) *big.Int {
	n, ok := new(big.Int).SetString(h, 16)
	if !ok {
		panic("srp: invalid hex constant")
	}
	return n
}

func sha256Bytes(bufs ...[]byte) []byte {
	h := sha256.New()
	for _, b := range bufs {
		h.Write(b)
	}
	return h.Sum(nil)
}

// padN left-pads a big.Int to N's byte-length (256 bytes), matching the JS
// SRPInteger.toHex() behavior for mod-N values.
func padN(i *big.Int) []byte {
	b := i.Bytes()
	if len(b) >= nBytes {
		return b
	}
	out := make([]byte, nBytes)
	copy(out[nBytes-len(b):], b)
	return out
}

func multiplier() *big.Int {
	// k = H(N | g) with g as the single byte 0x02.
	kb := sha256Bytes(padN(N), []byte{0x02})
	return new(big.Int).SetBytes(kb)
}

func hnXorHgConst() []byte {
	hn := sha256Bytes(padN(N))
	hg := sha256Bytes([]byte{0x02})
	out := make([]byte, len(hn))
	for i := range hn {
		out[i] = hn[i] ^ hg[i]
	}
	return out
}

// modPow computes base^exp mod m.
func modPow(base, exp, m *big.Int) *big.Int {
	return new(big.Int).Exp(base, exp, m)
}

// computeU returns u = H(A | B) with both padded to N-length.
func computeU(aHex, bHex string) (*big.Int, error) {
	a, err := hex.DecodeString(aHex)
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(bHex)
	if err != nil {
		return nil, err
	}
	ub := sha256Bytes(padNHex(a), padNHex(b))
	return new(big.Int).SetBytes(ub), nil
}

func padNHex(raw []byte) []byte {
	i := new(big.Int).SetBytes(raw)
	return padN(i)
}

// computeM1 returns M1 = H( H(N)^H(g) | H(I) | s | A | B | K ).
func computeM1(aHex, bHex, kHex, username, saltHex string) ([]byte, error) {
	hi := sha256Bytes([]byte(username))
	s, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, err
	}
	a, err := hex.DecodeString(aHex)
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(bHex)
	if err != nil {
		return nil, err
	}
	kb, err := hex.DecodeString(kHex)
	if err != nil {
		return nil, err
	}
	return sha256Bytes(hnXorHg, hi, s, padNHex(a), padNHex(b), kb), nil
}

// computeM2 returns M2 = H( A | M1 | K ).
func computeM2(aHex string, m1, kb []byte) ([]byte, error) {
	a, err := hex.DecodeString(aHex)
	if err != nil {
		return nil, err
	}
	return sha256Bytes(padNHex(a), m1, kb), nil
}

// ServerSession is the result of the server-side SRP derivation.
type ServerSession struct {
	// Key is the shared session key K = H(S).
	Key []byte
	// ServerProof is M2 = H(A | M1 | K), returned to the client.
	ServerProof []byte
}

// DeriveServerSession verifies the client's proof M1 and computes the session
// key K and server proof M2. It returns an error (and no session) if M1 is
// invalid or any input is malformed. This is the exact mirror of
// packages/crypto/src/srp/server.ts:deriveServerSession.
//
// Inputs are hex strings: b (server secret ephemeral), aPub (client public A),
// verifier v; username and saltHex feed the M1 proof; clientProofHex is M1.
func DeriveServerSession(serverSecretEphemeral, clientPublicEphemeral, saltHex, username, verifierHex, clientProofHex string) (*ServerSession, error) {
	b, ok := new(big.Int).SetString(serverSecretEphemeral, 16)
	if !ok {
		return nil, errBadInput
	}
	A, ok := new(big.Int).SetString(clientPublicEphemeral, 16)
	if !ok {
		return nil, errBadInput
	}
	v, ok := new(big.Int).SetString(verifierHex, 16)
	if !ok {
		return nil, errBadInput
	}

	// A % N must not be zero (guards against a malicious client).
	if new(big.Int).Mod(A, N).Sign() == 0 {
		return nil, errInvalidPublic
	}

	// B = (k*v + g^b) mod N
	B := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(K, v), modPow(G, b, N)), N)

	aHex := hex.EncodeToString(padN(A))
	bHex := hex.EncodeToString(padN(B))

	u, err := computeU(aHex, bHex)
	if err != nil {
		return nil, err
	}

	// S = (A * v^u)^b mod N
	S := modPow(new(big.Int).Mod(new(big.Int).Mul(A, modPow(v, u, N)), N), b, N)

	key := sha256Bytes(padN(S))
	keyHex := hex.EncodeToString(key)

	expectedM1, err := computeM1(aHex, bHex, keyHex, username, saltHex)
	if err != nil {
		return nil, err
	}
	clientProof, err := hex.DecodeString(clientProofHex)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(expectedM1, clientProof) != 1 {
		return nil, errBadProof
	}

	m2, err := computeM2(aHex, clientProof, key)
	if err != nil {
		return nil, err
	}
	return &ServerSession{Key: key, ServerProof: m2}, nil
}

// ServerPublicEphemeral computes B = (k*v + g^b) mod N as padded hex, given the
// server's secret ephemeral b (hex) and verifier v (hex). Used to mirror the JS
// generateEphemeral in tests.
func ServerPublicEphemeral(serverSecretEphemeral, verifierHex string) (string, error) {
	b, ok := new(big.Int).SetString(serverSecretEphemeral, 16)
	if !ok {
		return "", errBadInput
	}
	v, ok := new(big.Int).SetString(verifierHex, 16)
	if !ok {
		return "", errBadInput
	}
	B := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(K, v), modPow(G, b, N)), N)
	return hex.EncodeToString(padN(B)), nil
}
