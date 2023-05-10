package cryptokms_test

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"testing"
	"testing/iotest"

	"github.com/tprasadtp/cryptokms"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

//nolint:gocognit
func Test_VerifyDigest(t *testing.T) {
	type testCase struct {
		Name      string
		PublicKey crypto.PublicKey
		Digest    []byte
		Signature []byte
		Hash      crypto.Hash
		Err       error
	}
	tt := []testCase{
		{
			Name:      "valid-rsa2048-sha1",
			PublicKey: testkeys.GetRSA2048PublicKey(),
			Digest:    testkeys.KnownInputHash(crypto.SHA1),
			Hash:      crypto.SHA1,
			Signature: func() []byte {
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
			Name:      "valid-rsa2048-sha256",
			PublicKey: testkeys.GetRSA2048PublicKey(),
			Digest:    testkeys.KnownInputHash(crypto.SHA256),
			Hash:      crypto.SHA256,
			Signature: func() []byte {
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
			Name:      "valid-rsa4096-sha512",
			PublicKey: testkeys.GetRSA4096PublicKey(),
			Digest:    testkeys.KnownInputHash(crypto.SHA512),
			Hash:      crypto.SHA512,
			Signature: func() []byte {
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
			Name:      "valid-ecp256-sha256",
			PublicKey: testkeys.GetECP256PublicKey(),
			Digest:    testkeys.KnownInputHash(crypto.SHA256),
			Hash:      crypto.SHA256,
			Signature: func() []byte {
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
			Name:      "valid-ed25519-sha512",
			PublicKey: testkeys.GetED25519PublicKey(),
			Digest:    testkeys.KnownInputHash(crypto.SHA512),
			Hash:      crypto.SHA512,
			Signature: func() []byte {
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
			Name:      "ed25519-digest-mismatch",
			PublicKey: testkeys.GetED25519PublicKey(),
			Digest:    testkeys.KnownInputHash(crypto.SHA256),
			Hash:      crypto.SHA512,
			Err:       cryptokms.ErrDigestLength,
			Signature: func() []byte {
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
			Name:      "ed25519-digest-not-sha512",
			PublicKey: testkeys.GetED25519PublicKey(),
			Digest:    testkeys.KnownInputHash(crypto.SHA256),
			Hash:      crypto.SHA256,
			Err:       cryptokms.ErrSignatureEd25519,
			Signature: func() []byte {
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
			Name: "ed25519-signature-valid-but-wrong-key",
			PublicKey: func() ed25519.PublicKey {
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				return pub
			}(),
			Digest: testkeys.KnownInputHash(crypto.SHA512),
			Hash:   crypto.SHA512,
			Err:    cryptokms.ErrSignatureEd25519,
			Signature: func() []byte {
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
			Name:      "ed25519-signature-invalid",
			PublicKey: testkeys.GetED25519PublicKey(),
			Digest:    testkeys.KnownInputHash(crypto.SHA512),
			Hash:      crypto.SHA512,
			Err:       cryptokms.ErrSignatureEd25519,
			Signature: func() []byte {
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
			Name: "valid-ptr-ed25519-sha512",
			PublicKey: func() *ed25519.PublicKey {
				pub := testkeys.GetED25519PublicKey()
				return &pub
			}(),
			Digest: testkeys.KnownInputHash(crypto.SHA512),
			Hash:   crypto.SHA512,
			Signature: func() []byte {
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
			Name: "ed25519-ptr-digest-mismatch",
			PublicKey: func() *ed25519.PublicKey {
				pub := testkeys.GetED25519PublicKey()
				return &pub
			}(),
			Digest: testkeys.KnownInputHash(crypto.SHA256),
			Hash:   crypto.SHA512,
			Err:    cryptokms.ErrDigestLength,
			Signature: func() []byte {
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
			Name: "ed25519-ptr-digest-not-sha512",
			PublicKey: func() *ed25519.PublicKey {
				pub := testkeys.GetED25519PublicKey()
				return &pub
			}(),
			Digest: testkeys.KnownInputHash(crypto.SHA256),
			Hash:   crypto.SHA256,
			Err:    cryptokms.ErrSignatureEd25519,
			Signature: func() []byte {
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
			Name: "ed25519-ptr-signature-valid-but-wrong-key",
			PublicKey: func() *ed25519.PublicKey {
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				return &pub
			}(),
			Digest: testkeys.KnownInputHash(crypto.SHA512),
			Hash:   crypto.SHA512,
			Err:    cryptokms.ErrSignatureEd25519,
			Signature: func() []byte {
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
			Name:      "ed25519-signature-invalid",
			PublicKey: testkeys.GetED25519PublicKey(),
			Digest:    testkeys.KnownInputHash(crypto.SHA512),
			Hash:      crypto.SHA512,
			Err:       cryptokms.ErrSignatureEd25519,
			Signature: func() []byte {
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
			Name:      "invalid-rsa-signature-ec-public-key",
			PublicKey: testkeys.GetECP256PublicKey(),
			Digest:    testkeys.KnownInputHash(crypto.SHA256),
			Hash:      crypto.SHA256,
			Err:       cryptokms.ErrSignatureECDSA,
			Signature: func() []byte {
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
			Name:      "invalid-hash-length-mismatch",
			PublicKey: testkeys.GetECP256PublicKey(),
			Digest:    testkeys.KnownInputHash(crypto.SHA256),
			Hash:      crypto.SHA384,
			Err:       cryptokms.ErrDigestLength,
			Signature: func() []byte {
				signer := testkeys.GetECP256PrivateKey()
				signature, err := signer.Sign(
					rand.Reader, testkeys.KnownInputHash(crypto.SHA256), crypto.SHA256)
				if err != nil {
					t.Fatalf("failed to sign: %s", err)
				}
				return signature
			}(),
		},
		// invalid signature
		{
			Name:      "invalid-ec-signature",
			PublicKey: testkeys.GetECP256PublicKey(),
			Digest:    testkeys.KnownInputHash(crypto.SHA256),
			Hash:      crypto.SHA256,
			Err:       cryptokms.ErrSignatureECDSA,
			Signature: func() []byte {
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
			Name:      "invalid-rsa-signature",
			PublicKey: testkeys.GetRSA2048PublicKey(),
			Digest:    testkeys.KnownInputHash(crypto.SHA256),
			Hash:      crypto.SHA256,
			Err:       cryptokms.ErrSignatureRSA,
			Signature: func() []byte {
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
			Name:      "invalid-rsa-pss-signature",
			PublicKey: testkeys.GetRSA2048PublicKey(),
			Digest:    testkeys.KnownInputHash(crypto.SHA256),
			Hash:      crypto.SHA256,
			Err:       cryptokms.ErrSignatureRSA,
			Signature: func() []byte {
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
			Name:      "rsa-pss-signature-invalid-hash",
			PublicKey: testkeys.GetRSA2048PublicKey(),
			Digest:    testkeys.KnownInputHash(crypto.SHA256),
			Hash:      crypto.SHA256,
			Err:       cryptokms.ErrSignatureRSA,
			Signature: func() []byte {
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
			Name:      "rsa-pss-signature-valid",
			PublicKey: testkeys.GetRSA2048PublicKey(),
			Digest:    testkeys.KnownInputHash(crypto.SHA256),
			Hash:      crypto.SHA256,
			Signature: func() []byte {
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
		// key-mismatch-ecdsa
		{
			Name:      "correct-signature-wrong-ec-key",
			PublicKey: testkeys.GetECP256PublicKey(),
			Digest:    testkeys.KnownInputHash(crypto.SHA384),
			Hash:      crypto.SHA384,
			Err:       cryptokms.ErrSignatureECDSA,
			Signature: func() []byte {
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
			Name:      "correct-signature-wrong-rsa-key",
			PublicKey: testkeys.GetRSA4096PublicKey(),
			Digest:    testkeys.KnownInputHash(crypto.SHA256),
			Hash:      crypto.SHA256,
			Err:       cryptokms.ErrSignatureRSA,
			Signature: func() []byte {
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
			Name:      "correct-signature-wrong-rsa-key",
			PublicKey: nil,
			Digest:    testkeys.KnownInputHash(crypto.SHA256),
			Hash:      crypto.SHA256,
			Err:       cryptokms.ErrKeyAlgorithm,
			Signature: func() []byte {
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
		t.Run(tc.Name, func(t *testing.T) {
			err := cryptokms.VerifyDigestSignature(tc.PublicKey, tc.Hash, tc.Digest, tc.Signature)
			if !errors.Is(err, tc.Err) {
				t.Errorf("Expects error: %s, bit got: %s", tc.Err, err)
			}
		})
	}
}

// uselessReader implements [io.Reader] which always errors.
type uselessReader struct{}

// Always return [iotest.ErrTimeout] on Read.
func (uselessReader) Read(p []byte) (int, error) {
	return 0, fmt.Errorf("%w: useless reader always returns error", iotest.ErrTimeout)
}

func Test_Verify(t *testing.T) {
	type testCase struct {
		Name      string
		PublicKey crypto.PublicKey
		Data      io.Reader
		Signature []byte
		Hash      crypto.Hash
		Err       error
	}
	tt := []testCase{
		{
			Name:      "nil-data",
			PublicKey: testkeys.GetRSA2048PublicKey(),
			Data:      nil,
			Hash:      crypto.SHA256,
			Err:       cryptokms.ErrInvalidInput,
			Signature: func() []byte {
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
			Name:      "valid-rsa4096-sha512",
			PublicKey: testkeys.GetRSA4096PublicKey(),
			Data: func() *bytes.Buffer {
				b := &bytes.Buffer{}
				b.WriteString(testkeys.KnownInput)
				return b
			}(),
			Hash: crypto.SHA512,
			Signature: func() []byte {
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
			Name:      "valid-ecp256-sha256",
			PublicKey: testkeys.GetECP256PublicKey(),
			Data: func() *bytes.Buffer {
				b := &bytes.Buffer{}
				b.WriteString(testkeys.KnownInput)
				return b
			}(),
			Hash: crypto.SHA256,
			Signature: func() []byte {
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
			Name:      "reader-error",
			PublicKey: testkeys.GetECP256PublicKey(),
			Data:      &uselessReader{},
			Err:       iotest.ErrTimeout,
			Hash:      crypto.SHA256,
			Signature: func() []byte {
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
		t.Run(tc.Name, func(t *testing.T) {
			err := cryptokms.VerifySignature(tc.PublicKey, tc.Hash, tc.Data, tc.Signature)
			if !errors.Is(err, tc.Err) {
				t.Errorf("Expects error: %s, bit got: %s", tc.Err, err)
			}
		})
	}
}
