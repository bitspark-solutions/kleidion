package srp

import "errors"

var (
	// errBadInput signals malformed hex or unparsable big-integer input.
	errBadInput = errors.New("srp: invalid input encoding")
	// errInvalidPublic signals an ephemeral public value that is 0 mod N.
	errInvalidPublic = errors.New("srp: invalid public ephemeral value")
	// errBadProof signals that the client's M1 proof did not match.
	errBadProof = errors.New("srp: client proof invalid")
)
