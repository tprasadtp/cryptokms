package ioutils

import (
	"crypto"
	"errors"
	"fmt"
	"io"
)

// ErrDigestAlgorithmUnavailable is returned when specified hash algorithm is not
// linked in the binary.
var ErrDigestAlgorithmUnavailable = errors.New("cryptokms(ioutils): digest algorithm is not linked in binary or invalid")

// Hashes by reading from io.Reader with specified hash.
func HashBlob(in io.Reader, hash crypto.Hash) ([]byte, error) {
	if !hash.Available() {
		return nil, ErrDigestAlgorithmUnavailable
	}

	h := hash.New()
	if _, err := io.Copy(h, in); err != nil {
		return nil, fmt.Errorf("cryptokms: failed to hash data: %w", err)
	}
	return h.Sum(nil), nil
}
