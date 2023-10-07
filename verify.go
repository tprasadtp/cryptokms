// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

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
)

// VerifyDigestSignature is a wrapper around following, used to verify asymmetric signatures.
//   - [crypto/rsa.VerifyPKCS1v15]
//   - [crypto/ecdsa.Verify]
//   - [crypto/ed25519.VerifyWithOptions]
//   - [crypto/rsa.VerifyPSS]
//
// Even though keys may be backed by KMS, this does not make use of KMS APIs
// for verifying signatures, instead uses locally available Public keys.
//
// For 25519 signatures, only Ed25519ph is supported with (SHA512).
//
// Public key must of one of
//   - *[crypto/rsa.PublicKey]
//   - *[crypto/ecdsa.PublicKey]
//   - [crypto/ed25519.PublicKey]
//   - *[crypto/ed25519.PublicKey]
//
// This does not allow insecure hashing algorithms ([crypto.SHA1] and [crypto.MD5],
// [crypto.MD4]) and returns an error even though signature might be valid.
// Similarly, RSA keys of length less than 2048 bits and ECDSA keys of size less than 256
// are rejected even though signature might be valid.
func VerifyDigestSignature(pub crypto.PublicKey, hash crypto.Hash, digest, signature []byte) error {
	if hash == crypto.SHA1 || hash == crypto.MD4 || hash == crypto.MD5 {
		return fmt.Errorf("cryptokms(verify): %s signatures are insecure are not supported", hash)
	}

	switch v := pub.(type) {
	case *rsa.PublicKey:
		if v.N.BitLen() < 2048 {
			return fmt.Errorf("cryptokms(verify): insecure RSA key size (%d) is less than 2048", v.N.BitLen())
		}

		pkcs1v15 := rsa.VerifyPKCS1v15(v, hash, digest, signature)
		if pkcs1v15 == nil {
			return nil
		}
		pss := rsa.VerifyPSS(v, hash, digest, signature, nil)
		if pss == nil {
			return nil
		}
		return fmt.Errorf("cryptokms(verify): RSA signature verification failed")
	case *ecdsa.PublicKey:
		if v.Curve.Params().BitSize < 256 {
			return fmt.Errorf("cryptokms(verify): ECDSA key size(%d) is less than 256 bits",
				v.Curve.Params().BitSize)
		}

		var ps struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(signature, &ps); err != nil {
			return fmt.Errorf("cryptokms(verify): ECDSA failed to unmarshal public key: %w", err)
		}
		if ecdsa.Verify(v, digest, ps.R, ps.S) {
			return nil
		}
		return fmt.Errorf("cryptokms(verify): ECDSA signature verification failed")
	// https://github.com/golang/go/issues/51974
	// ed25519 both cases need to be handled.
	case ed25519.PublicKey:
		// Skips check for digest size as verifier already does it.
		err := ed25519.VerifyWithOptions(v, digest, signature, &ed25519.Options{Hash: crypto.SHA512})
		if err == nil {
			return nil
		}
		return fmt.Errorf("cryptokms(verify): ed25519 signature verification failed: %w", err)
	case *ed25519.PublicKey:
		// Skips check for digest size as verifier already does it.
		err := ed25519.VerifyWithOptions(*v, digest, signature, &ed25519.Options{Hash: crypto.SHA512})
		if err == nil {
			return nil
		}
		return fmt.Errorf("cryptokms(verify): ed25519 signature verification failed: %w", err)
	default:
		return fmt.Errorf("cryptokms(verify): unknown key type: %T", pub)
	}
}

// VerifySignature is a wrapper around VerifyDigestSignature,
// but accepts an io.Reader, which can hash the data with given hash function.
func VerifySignature(pub crypto.PublicKey, hash crypto.Hash, in io.Reader, signature []byte) error {
	if in == nil {
		return fmt.Errorf("cryptokms(verify): input is nil")
	}

	if !hash.Available() {
		return fmt.Errorf("cryptokms(verify): digest algorithm(%s) is not available", hash)
	}

	h := hash.New()
	if _, err := io.Copy(h, in); err != nil {
		return fmt.Errorf("cryptokms(verify): failed to hash data: %w", err)
	}

	return VerifyDigestSignature(pub, hash, h.Sum(nil), signature)
}
