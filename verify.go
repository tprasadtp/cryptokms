package cryptokms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
)

const (
	// ErrSignatureRSA is returned when RSA signature verification fails.
	ErrSignatureRSA = Error("cryptokms: RSA signature verification failed")

	// ErrSignatureECDSA is returned when ECDSA signature verification fails.
	ErrSignatureECDSA = Error("cryptokms: ECDSA signature verification failed")
)

// VerifyDigestSignature is a wrapper around [crypto/rsa.VerifyPKCS1v15] and [crypto/ecdsa.Verify]
// and used to verify asymmetric signatures. Even though keys are backed by KMS, this does not
// use KMS APIs for verifying signatures, instead uses Public keys.
func VerifyDigestSignature(pub crypto.PublicKey, hash crypto.Hash, digest, signature []byte) error {
	if len(digest) != hash.Size() {
		return fmt.Errorf(
			"%w: digest length is %d, want %d",
			ErrDigestLength, len(digest), hash.Size(),
		)
	}

	switch v := pub.(type) {
	case *rsa.PublicKey:
		err := rsa.VerifyPKCS1v15(v, hash, digest, signature)
		if err == nil {
			return nil
		}
		return fmt.Errorf("%w: %w", ErrSignatureRSA, err)
	case *ecdsa.PublicKey:
		var ps struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(signature, &ps); err != nil {
			return fmt.Errorf("%w: failed to asn1.Unmarshal: %w", ErrSignatureECDSA, err)
		}
		if ecdsa.Verify(v, digest, ps.R, ps.S) {
			return nil
		}
		return ErrSignatureECDSA
	}
	return fmt.Errorf("%w: unknown public key type - %T", ErrKeyAlgorithm, pub)
}

// VerifySignature is a wrapper around VerifyDigestSignature,
// but accepts an io.Reader, which can hash the data with given hash function.
func VerifySignature(pub crypto.PublicKey, hash crypto.Hash, data io.Reader, signature []byte) error {
	if data == nil {
		return fmt.Errorf("%w: data is nil", ErrInvalidInput)
	}

	h := hash.New()
	if _, err := io.Copy(h, data); err != nil {
		return fmt.Errorf("cryptokms: failed to hash data: %w", err)
	}
	return VerifyDigestSignature(pub, hash, h.Sum(nil), signature)
}
