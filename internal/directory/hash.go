package directory

import "crypto/sha256"

func sha256Sum(v string) []byte {
	h := sha256.Sum256([]byte(v))
	out := make([]byte, len(h))
	copy(out, h[:])
	return out
}
