// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package cryptokms_test

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"testing"
	"testing/iotest"

	//nolint:gosec // only used for testing
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"

	"github.com/tprasadtp/cryptokms"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

func TestVerifyDigest(t *testing.T) {
	type testCase struct {
		name      string
		pub       crypto.PublicKey
		digest    []byte
		signature []byte
		hash      crypto.Hash
		ok        bool
	}
	tt := []testCase{
		{
			name:   "insecure-rsa1024-sha256",
			pub:    testkeys.GetRSA1024PublicKey(),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			hash:   crypto.SHA256,
			signature: func() []byte {
				signer := testkeys.GetRSA1024PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA256), crypto.SHA256)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
		{
			name:   "insecure-rsa2048-sha1",
			pub:    testkeys.GetRSA2048PublicKey(),
			digest: testkeys.KnownInputHash(crypto.SHA1),
			hash:   crypto.SHA1,
			signature: func() []byte {
				signer := testkeys.GetRSA2048PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA1), crypto.SHA1)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
		{
			name:   "valid-rsa2048-sha256",
			pub:    testkeys.GetRSA2048PublicKey(),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			hash:   crypto.SHA256,
			ok:     true,
			signature: func() []byte {
				signer := testkeys.GetRSA2048PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA256), crypto.SHA256)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
		{
			name:   "valid-rsa4096-sha512",
			pub:    testkeys.GetRSA4096PublicKey(),
			digest: testkeys.KnownInputHash(crypto.SHA512),
			hash:   crypto.SHA512,
			ok:     true,
			signature: func() []byte {
				signer := testkeys.GetRSA4096PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA512), crypto.SHA512)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
		{
			name:   "insecure-ecp2224-sha224",
			pub:    testkeys.GetECP224PublicKey(),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			hash:   crypto.SHA224,
			signature: func() []byte {
				signer := testkeys.GetECP224PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA224), crypto.SHA224)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
		{
			name:   "valid-ecp256-sha256",
			pub:    testkeys.GetECP256PublicKey(),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			hash:   crypto.SHA256,
			ok:     true,
			signature: func() []byte {
				signer := testkeys.GetECP256PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA256), crypto.SHA256)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
		// ED 25519 keys
		{
			name:   "valid-ed25519-sha512",
			pub:    testkeys.GetED25519PublicKey(),
			digest: testkeys.KnownInputHash(crypto.SHA512),
			hash:   crypto.SHA512,
			ok:     true,
			signature: func() []byte {
				signer := testkeys.GetED25519PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA512), crypto.SHA512)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
		{
			name:   "ed25519-digest-mismatch",
			pub:    testkeys.GetED25519PublicKey(),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			hash:   crypto.SHA512,
			signature: func() []byte {
				signer := testkeys.GetED25519PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA512), crypto.SHA512)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
		{
			name:   "ed25519-digest-not-sha512",
			pub:    testkeys.GetED25519PublicKey(),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			hash:   crypto.SHA256,
			signature: func() []byte {
				signer := testkeys.GetED25519PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA512), crypto.SHA512)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
		{
			name: "ed25519-signature-valid-but-wrong-key",
			pub: func() ed25519.PublicKey {
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				return pub
			}(),
			digest: testkeys.KnownInputHash(crypto.SHA512),
			hash:   crypto.SHA512,
			signature: func() []byte {
				signer := testkeys.GetED25519PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA512), crypto.SHA512)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
		{
			name:   "ed25519-signature-invalid",
			pub:    testkeys.GetED25519PublicKey(),
			digest: testkeys.KnownInputHash(crypto.SHA512),
			hash:   crypto.SHA512,
			signature: func() []byte {
				signer := testkeys.GetED25519PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA512), crypto.SHA512)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				// purposefully return invalid signature
				return signature[1:]
			}(),
		},
		// ED25529 as pointer
		{
			name: "valid-ptr-ed25519-sha512",
			pub: func() *ed25519.PublicKey {
				pub := testkeys.GetED25519PublicKey()
				return &pub
			}(),
			ok:     true,
			digest: testkeys.KnownInputHash(crypto.SHA512),
			hash:   crypto.SHA512,
			signature: func() []byte {
				signer := testkeys.GetED25519PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA512), crypto.SHA512)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
		{
			name: "ed25519-ptr-digest-mismatch",
			pub: func() *ed25519.PublicKey {
				pub := testkeys.GetED25519PublicKey()
				return &pub
			}(),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			hash:   crypto.SHA512,
			signature: func() []byte {
				signer := testkeys.GetED25519PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA512), crypto.SHA512)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
		{
			name: "ed25519-ptr-digest-not-sha512",
			pub: func() *ed25519.PublicKey {
				pub := testkeys.GetED25519PublicKey()
				return &pub
			}(),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			hash:   crypto.SHA256,
			signature: func() []byte {
				signer := testkeys.GetED25519PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA512), crypto.SHA512)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
		{
			name: "ed25519-ptr-signature-valid-but-wrong-key",
			pub: func() *ed25519.PublicKey {
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				return &pub
			}(),
			digest: testkeys.KnownInputHash(crypto.SHA512),
			hash:   crypto.SHA512,
			signature: func() []byte {
				signer := testkeys.GetED25519PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA512), crypto.SHA512)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
		{
			name:   "ed25519-signature-invalid",
			pub:    testkeys.GetED25519PublicKey(),
			digest: testkeys.KnownInputHash(crypto.SHA512),
			hash:   crypto.SHA512,
			signature: func() []byte {
				signer := testkeys.GetED25519PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA512), crypto.SHA512)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				// purposefully return invalid signature
				return signature[1:]
			}(),
		},
		// Key mismatch.
		{
			name:   "invalid-rsa-signature-ec-public-key",
			pub:    testkeys.GetECP256PublicKey(),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			hash:   crypto.SHA256,
			signature: func() []byte {
				signer := testkeys.GetRSA2048PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA256), crypto.SHA256)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
		//  hash length mismatch
		{
			name:   "invalid-hash-length-mismatch",
			pub:    testkeys.GetECP256PublicKey(),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			hash:   crypto.SHA384,
			signature: func() []byte {
				signer := testkeys.GetECP256PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA256), crypto.SHA256)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature[1:]
			}(),
		},
		// invalid signature
		{
			name:   "invalid-ec-signature",
			pub:    testkeys.GetECP256PublicKey(),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			hash:   crypto.SHA256,
			signature: func() []byte {
				signer := testkeys.GetECP256PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA256), crypto.SHA256)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				// purposefully return invalid signature
				return signature[1:]
			}(),
		},
		{
			name:   "invalid-rsa-signature",
			pub:    testkeys.GetRSA2048PublicKey(),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			hash:   crypto.SHA256,
			signature: func() []byte {
				signer := testkeys.GetRSA2048PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA256), crypto.SHA256)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				// purposefully return invalid signature
				return signature[1:]
			}(),
		},
		// RSA PSS
		{
			name:   "invalid-rsa-pss-signature",
			pub:    testkeys.GetRSA2048PublicKey(),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			hash:   crypto.SHA256,
			signature: func() []byte {
				signer := testkeys.GetRSA2048PrivateKey()
				signature, err := signer.Sign(
					rand.Reader,
					testkeys.KnownInputHash(crypto.SHA256),
					&rsa.PSSOptions{
						SaltLength: crypto.SHA256.Size(),
						Hash:       crypto.SHA256,
					})
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				// purposefully return invalid signature
				return signature[1:]
			}(),
		},
		{
			name:   "rsa-pss-signature-invalid-hash",
			pub:    testkeys.GetRSA2048PublicKey(),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			hash:   crypto.SHA256,
			signature: func() []byte {
				signer := testkeys.GetRSA2048PrivateKey()
				signature, err := signer.Sign(
					rand.Reader,
					testkeys.KnownInputHash(crypto.SHA512),
					&rsa.PSSOptions{
						SaltLength: crypto.SHA512.Size(),
						Hash:       crypto.SHA512,
					})
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
		{
			name:   "rsa-pss-signature-valid",
			pub:    testkeys.GetRSA2048PublicKey(),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			hash:   crypto.SHA256,
			ok:     true,
			signature: func() []byte {
				signer := testkeys.GetRSA2048PrivateKey()
				signature, err := signer.Sign(
					rand.Reader,
					testkeys.KnownInputHash(crypto.SHA256),
					&rsa.PSSOptions{
						SaltLength: crypto.SHA256.Size(),
						Hash:       crypto.SHA256,
					})
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
		{
			name:   "rsa-pss-signature-valid-default-options",
			pub:    testkeys.GetRSA2048PublicKey(),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			hash:   crypto.SHA256,
			ok:     true,
			signature: func() []byte {
				signer := testkeys.GetRSA2048PrivateKey()
				signature, err := signer.Sign(
					rand.Reader,
					testkeys.KnownInputHash(crypto.SHA256),
					&rsa.PSSOptions{
						Hash: crypto.SHA256,
					})
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
		// key-mismatch-ecdsa
		{
			name:   "correct-signature-wrong-ec-key",
			pub:    testkeys.GetECP256PublicKey(),
			digest: testkeys.KnownInputHash(crypto.SHA384),
			hash:   crypto.SHA384,
			signature: func() []byte {
				signer := testkeys.GetECP384PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA384), crypto.SHA384)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
		{
			name:   "correct-signature-wrong-rsa-key",
			pub:    testkeys.GetRSA4096PublicKey(),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			hash:   crypto.SHA256,
			signature: func() []byte {
				signer := testkeys.GetRSA2048PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA256), crypto.SHA256)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
		// invalid public key
		{
			name:   "correct-signature-wrong-rsa-key",
			pub:    nil,
			digest: testkeys.KnownInputHash(crypto.SHA256),
			hash:   crypto.SHA256,
			signature: func() []byte {
				signer := testkeys.GetRSA2048PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA256), crypto.SHA256)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			err := cryptokms.VerifyDigestSignature(tc.pub, tc.hash, tc.digest, tc.signature)
			if tc.ok {
				if err != nil {
					t.Errorf("expected no error, but got %s", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error, but got nil")
				}
			}
		})
	}
}

// uselessReader implements [io.Reader] which always errors.
type uselessReader struct{}

// Always return [iotest.ErrTimeout] on Read.
func (uselessReader) Read(_ []byte) (int, error) {
	return 0, fmt.Errorf("%w: useless reader always returns error", iotest.ErrTimeout)
}

func Test_Verify(t *testing.T) {
	type testCase struct {
		name string
		pub  crypto.PublicKey
		data io.Reader
		sig  []byte
		hash crypto.Hash
		ok   bool
	}
	tt := []testCase{
		{
			name: "nil-data",
			pub:  testkeys.GetRSA2048PublicKey(),
			data: nil,
			hash: crypto.SHA256,
			sig: func() []byte {
				signer := testkeys.GetRSA2048PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA256), crypto.SHA256)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
		{
			name: "unsupported-hash-algorithm",
			pub:  testkeys.GetECP256PublicKey(),
			data: func() *bytes.Buffer {
				b := &bytes.Buffer{}
				b.WriteString(testkeys.KnownInput)
				return b
			}(),
			hash: crypto.Hash(0),
			sig: func() []byte {
				signer := testkeys.GetECP256PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA256), crypto.SHA256)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
		{
			name: "valid-rsa4096-sha512",
			pub:  testkeys.GetRSA4096PublicKey(),
			data: func() *bytes.Buffer {
				b := &bytes.Buffer{}
				b.WriteString(testkeys.KnownInput)
				return b
			}(),
			hash: crypto.SHA512,
			ok:   true,
			sig: func() []byte {
				signer := testkeys.GetRSA4096PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA512), crypto.SHA512)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
		{
			name: "valid-ecp256-sha256",
			pub:  testkeys.GetECP256PublicKey(),
			ok:   true,
			data: func() *bytes.Buffer {
				b := &bytes.Buffer{}
				b.WriteString(testkeys.KnownInput)
				return b
			}(),
			hash: crypto.SHA256,
			sig: func() []byte {
				signer := testkeys.GetECP256PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA256), crypto.SHA256)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
		{
			name: "reader-error",
			pub:  testkeys.GetECP256PublicKey(),
			data: &uselessReader{},
			hash: crypto.SHA256,
			sig: func() []byte {
				signer := testkeys.GetECP256PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA256), crypto.SHA256)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			err := cryptokms.VerifySignature(tc.pub, tc.hash, tc.data, tc.sig)
			if tc.ok {
				if err != nil {
					t.Errorf("expected no error, but got %s", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error, but got nil")
				}
			}
		})
	}
}
