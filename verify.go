package cryptokms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"

	"github.com/tprasadtp/cryptokms/internal/ioutils"
)

const (
	// ErrSignatureRSA is returned when RSA signature verification fails.
	ErrSignatureRSA = Error("cryptokms: RSA signature verification failed")

	// ErrSignatureECDSA is returned when ECDSA signature verification fails.
	ErrSignatureECDSA = Error("cryptokms: ECDSA signature verification failed")

	// ErrSignatureEd25519 is returned when ed25519 signature verification fails.
	ErrSignatureEd25519 = Error("cryptokms: ed25519 signature verification failed")
)

// VerifyDigestSignature is a wrapper around following, used to verify asymmetric signatures.
//   - [crypto/rsa.VerifyPKCS1v15]
//   - [crypto/ecdsa.Verify]
//   - [crypto/ed25519.VerifyWithOptions]
//
// Even though keys may be backed by KMS, this does not make use of KMS APIs
// for verifying signatures, instead uses locally available Public keys.
//
// For ed25519 signatures, only Ed25519ph is supported with (SHA512).
//
// Public key must of one of
//   - *[crypto/rsa.PublicKey]
//   - *[crypto/ecdsa.PublicKey]
//   - [crypto/ed25519.PublicKey]
//   - *[crypto/ed25519.PublicKey]
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
	// https://github.com/golang/go/issues/51974
	// ed25519 both cases need to be handled.
	case ed25519.PublicKey:
		if hash != crypto.SHA512 {
			return fmt.Errorf("%w: digest algorithm(%s) not supported, ed25519 uses SHA512",
				ErrSignatureEd25519, hash)
		}
		err := ed25519.VerifyWithOptions(v, digest, signature, &ed25519.Options{Hash: crypto.SHA512})
		if err == nil {
			return nil
		}
		return fmt.Errorf("%w: %w", ErrSignatureEd25519, err)
	case *ed25519.PublicKey:
		if hash != crypto.SHA512 {
			return fmt.Errorf("%w: digest algorithm(%s) not supported, ed25519 uses SHA512",
				ErrSignatureEd25519, hash)
		}
		err := ed25519.VerifyWithOptions(*v, digest, signature,
			&ed25519.Options{
				Hash: crypto.SHA512,
			})
		if err == nil {
			return nil
		}
		return fmt.Errorf("%w: %w", ErrSignatureEd25519, err)
	}
	return fmt.Errorf("%w: unknown public key type - %T", ErrKeyAlgorithm, pub)
}

// VerifySignature is a wrapper around VerifyDigestSignature,
// but accepts an io.Reader, which can hash the data with given hash function.
func VerifySignature(pub crypto.PublicKey, hash crypto.Hash, data io.Reader, signature []byte) error {
	if data == nil {
		return fmt.Errorf("%w: data is nil", ErrInvalidInput)
	}

	digest, err := ioutils.HashBlob(data, hash)
	if err != nil {
		return fmt.Errorf("cryptokms: failed to hash data: %w", err)
	}
	return VerifyDigestSignature(pub, hash, digest, signature)
}
