// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package filekms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/tprasadtp/cryptokms"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

func TestNewSigner(t *testing.T) {
	dir := t.TempDir()
	type testCase struct {
		Name        string
		Path        string
		Response    *Signer
		ResponseErr error
		Valid       bool
	}
	tt := []testCase{
		{
			Name:        "rsa-1024",
			Path:        "internal/testdata/rsa-1024.pem",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name: "rsa-2048",
			Path: "internal/testdata/rsa-2048.pem",
			Response: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA2048,
			},
			Valid: true,
		},
		{
			Name: "rsa-3072",
			Path: "internal/testdata/rsa-3072.pem",
			Response: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA3072,
			},
			Valid: true,
		},
		{
			Name: "rsa-4096",
			Path: "internal/testdata/rsa-4096.pem",
			Response: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA4096,
			},
			Valid: true,
		},
		{
			Name: "ec-p256",
			Path: "internal/testdata/ec-p256.pem",
			Response: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmECP256,
			},
			Valid: true,
		},
		{
			Name: "ec-p384",
			Path: "internal/testdata/ec-p384.pem",
			Response: &Signer{
				hash: crypto.SHA384,
				algo: cryptokms.AlgorithmECP384,
			},
			Valid: true,
		},
		{
			Name: "ec-p521",
			Path: "internal/testdata/ec-p521.pem",
			Response: &Signer{
				hash: crypto.SHA512,
				algo: cryptokms.AlgorithmECP521,
			},
			Valid: true,
		},
		{
			Name: "ed-25519",
			Path: "internal/testdata/ed-25519.pem",
			Response: &Signer{
				hash: crypto.SHA512,
				algo: cryptokms.AlgorithmED25519,
			},
			Valid: true,
		},
		{
			Name:        "non-existing-file",
			Path:        filepath.Join(dir, "non-existing-file.pem"),
			ResponseErr: os.ErrNotExist,
		},
		{
			Name: "not-a-file",
			Path: dir,
		},
		{
			Name: "empty-file",
			Path: "internal/testdata/.gitkeep",
		},
		{
			Name: "public-key-file",
			Path: "../gcpkms/internal/testdata/rsa-sign-pkcs1-4096-sha512.pub",
		},
		{
			Name: "file-size-too-large",
			Path: func() string {
				file, err := os.CreateTemp(dir, "file-size-too-large-*.pem")
				if err != nil {
					t.Fatalf("failed to create temp file: %s", err)
				}
				defer file.Close()
				b := make([]byte, 9e3)
				h := make([]byte, hex.EncodedLen(9e3))
				_, err = rand.Read(b)
				if err != nil {
					t.Fatalf("failed to generate random bytes: %s", err)
				}
				hex.Encode(h, b)
				_, err = file.Write(h)
				if err != nil {
					t.Fatalf("failed to write random bytes: %s", err)
				}
				return file.Name()
			}(),
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			resp, err := NewSigner(tc.Path)
			diff := cmp.Diff(
				resp, tc.Response,
				cmp.AllowUnexported(Signer{}),
				cmpopts.IgnoreFields(Signer{}, "mu", "signer", "pub", "ts"))
			if diff != "" {
				t.Errorf("did not get expected response: \n%s", diff)
			}

			if !tc.Valid {
				if tc.ResponseErr != nil {
					if !errors.Is(err, tc.ResponseErr) {
						t.Errorf("expected error=%#v, but got=%#v", tc.ResponseErr, err)
					}
				} else {
					if err == nil {
						t.Errorf("expected non nil error")
					}
				}
			} else {
				if resp.Algorithm() != tc.Response.algo {
					t.Errorf("expected algo=%d, got=%d", tc.Response.algo, resp.Algorithm())
				}
				if resp.CreatedAt().IsZero() {
					t.Errorf("expected CreatedAt() to return non zero, got %s", resp.CreatedAt())
				}
				if resp.HashFunc() != tc.Response.hash {
					t.Errorf("expected HashFunc()=%s, got %s", tc.Response.hash, resp.HashFunc())
				}
			}
		})
	}
}

func TestSigner_Sign_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	signer, _ := NewSigner("internal/testdata/ec-p256.pem")
	_, err := signer.SignContext(ctx, rand.Reader, testkeys.KnownInputHash(crypto.SHA256), nil)
	if !errors.Is(err, cryptokms.ErrAsymmetricSign) {
		t.Errorf("expected error(ErrAsymmetricSign) when ctx is already cancelled")
	}
}

func TestSigner_Sign(t *testing.T) {
	type testCase struct {
		Name        string
		KeyFile     string
		Digest      []byte
		Options     crypto.SignerOpts
		ResponseErr error
	}
	tt := []testCase{
		{
			Name:    "rsa-2048-default-hash",
			KeyFile: "internal/testdata/rsa-2048.pem",
			Digest:  testkeys.KnownInputHash(crypto.SHA256),
		},
		{
			Name:    "rsa-2048-with-sha-256",
			KeyFile: "internal/testdata/rsa-2048.pem",
			Digest:  testkeys.KnownInputHash(crypto.SHA256),
			Options: crypto.SHA256,
		},
		{
			Name:    "rsa-2048-with-sha-384",
			KeyFile: "internal/testdata/rsa-2048.pem",
			Digest:  testkeys.KnownInputHash(crypto.SHA384),
			Options: crypto.SHA384,
		},
		{
			Name:    "rsa-2048-with-sha-512",
			KeyFile: "internal/testdata/rsa-2048.pem",
			Digest:  testkeys.KnownInputHash(crypto.SHA512),
			Options: crypto.SHA512,
		},
		{
			Name:        "rsa-2048-with-sha-512-invalid-hash",
			KeyFile:     "internal/testdata/rsa-2048.pem",
			Digest:      testkeys.KnownInputHash(crypto.SHA1),
			Options:     crypto.SHA512,
			ResponseErr: cryptokms.ErrDigestLength,
		},
		{
			Name:    "rsa-2048-with-pss-options-empty",
			KeyFile: "internal/testdata/rsa-2048.pem",
			Digest:  testkeys.KnownInputHash(crypto.SHA256),
			Options: &rsa.PSSOptions{},
		},
		{
			Name:    "rsa-2048-with-pss-options-hash-only",
			KeyFile: "internal/testdata/rsa-2048.pem",
			Digest:  testkeys.KnownInputHash(crypto.SHA256),
			Options: &rsa.PSSOptions{Hash: crypto.SHA256},
		},
		{
			Name:    "rsa-2048-with-pss-options-hash-and-saltlen",
			KeyFile: "internal/testdata/rsa-2048.pem",
			Digest:  testkeys.KnownInputHash(crypto.SHA256),
			Options: &rsa.PSSOptions{
				Hash:       crypto.SHA256,
				SaltLength: crypto.SHA256.HashFunc().Size(),
			},
		},
		{
			Name:    "rsa-2048-with-pss-options-hash-and-saltlen-mismatch",
			KeyFile: "internal/testdata/rsa-2048.pem",
			Digest:  testkeys.KnownInputHash(crypto.SHA256),
			Options: &rsa.PSSOptions{
				Hash:       crypto.SHA256,
				SaltLength: crypto.SHA512.HashFunc().Size(),
			},
			ResponseErr: cryptokms.ErrSignerOpts,
		},
		{
			Name:    "rsa-2048-with-pss-options-hash-len-mismatch",
			KeyFile: "internal/testdata/rsa-2048.pem",
			Digest:  testkeys.KnownInputHash(crypto.SHA1),
			Options: &rsa.PSSOptions{
				Hash: crypto.SHA256,
			},
			ResponseErr: cryptokms.ErrDigestLength,
		},
		// P-256
		{
			Name:    "ec-p256-default",
			KeyFile: "internal/testdata/ec-p256.pem",
			Digest:  testkeys.KnownInputHash(crypto.SHA256),
		},
		{
			Name:    "ec-p256-sha256",
			KeyFile: "internal/testdata/ec-p256.pem",
			Digest:  testkeys.KnownInputHash(crypto.SHA256),
			Options: crypto.SHA256,
		},
		{
			Name:        "ec-p256-invalid-hash-sha512",
			KeyFile:     "internal/testdata/ec-p256.pem",
			Digest:      testkeys.KnownInputHash(crypto.SHA512),
			Options:     crypto.SHA512,
			ResponseErr: cryptokms.ErrDigestAlgorithm,
		},
		{
			Name:        "ec-p256-sha256-hash-mismatch",
			KeyFile:     "internal/testdata/ec-p256.pem",
			Digest:      testkeys.KnownInputHash(crypto.SHA1),
			Options:     crypto.SHA256,
			ResponseErr: cryptokms.ErrDigestLength,
		},
		{
			Name:    "ec-p256-sha256-pss-options",
			KeyFile: "internal/testdata/ec-p256.pem",
			Digest:  testkeys.KnownInputHash(crypto.SHA256),
			Options: &rsa.PSSOptions{
				Hash:       crypto.SHA256,
				SaltLength: crypto.SHA256.Size(),
			},
			ResponseErr: cryptokms.ErrSignerOpts,
		},
		// P384
		{
			Name:    "ec-p384",
			KeyFile: "internal/testdata/ec-p384.pem",
			Digest:  testkeys.KnownInputHash(crypto.SHA384),
		},
		{
			Name:    "ec-p384-sha384",
			KeyFile: "internal/testdata/ec-p384.pem",
			Digest:  testkeys.KnownInputHash(crypto.SHA384),
			Options: crypto.SHA384,
		},
		{
			Name:        "ec-p384-invalid-hash-sha512",
			KeyFile:     "internal/testdata/ec-p384.pem",
			Digest:      testkeys.KnownInputHash(crypto.SHA512),
			Options:     crypto.SHA512,
			ResponseErr: cryptokms.ErrDigestAlgorithm,
		},
		{
			Name:        "ec-p384-sha384-hash-mismatch",
			KeyFile:     "internal/testdata/ec-p384.pem",
			Digest:      testkeys.KnownInputHash(crypto.SHA1),
			ResponseErr: cryptokms.ErrDigestLength,
		},
		{
			Name:    "ec-p384-sha384-pss-options",
			KeyFile: "internal/testdata/ec-p384.pem",
			Digest:  testkeys.KnownInputHash(crypto.SHA384),
			Options: &rsa.PSSOptions{
				Hash:       crypto.SHA384,
				SaltLength: crypto.SHA384.Size(),
			},
			ResponseErr: cryptokms.ErrSignerOpts,
		},
		// P521
		{
			Name:    "ec-p521",
			KeyFile: "internal/testdata/ec-p521.pem",
			Digest:  testkeys.KnownInputHash(crypto.SHA512),
		},
		{
			Name:    "ec-p521-sha512",
			KeyFile: "internal/testdata/ec-p521.pem",
			Digest:  testkeys.KnownInputHash(crypto.SHA512),
			Options: crypto.SHA512,
		},
		{
			Name:        "ec-p521-invalid-hash-sha256",
			KeyFile:     "internal/testdata/ec-p521.pem",
			Digest:      testkeys.KnownInputHash(crypto.SHA256),
			Options:     crypto.SHA256,
			ResponseErr: cryptokms.ErrDigestAlgorithm,
		},
		{
			Name:        "ec-p521-sha521-hash-mismatch",
			KeyFile:     "internal/testdata/ec-p521.pem",
			Digest:      testkeys.KnownInputHash(crypto.SHA1),
			ResponseErr: cryptokms.ErrDigestLength,
		},
		{
			Name:    "ec-p521-sha521-pss-options",
			KeyFile: "internal/testdata/ec-p521.pem",
			Digest:  testkeys.KnownInputHash(crypto.SHA512),
			Options: &rsa.PSSOptions{
				Hash:       crypto.SHA512,
				SaltLength: crypto.SHA512.Size(),
			},
			ResponseErr: cryptokms.ErrSignerOpts,
		},
		// ED25529
		{
			Name:    "ed-25519",
			KeyFile: "internal/testdata/ed-25519.pem",
			Digest:  testkeys.KnownInputHash(crypto.SHA512),
		},
		{
			Name:    "ed-25519-sha512",
			KeyFile: "internal/testdata/ed-25519.pem",
			Digest:  testkeys.KnownInputHash(crypto.SHA512),
			Options: crypto.SHA512,
		},
		{
			Name:        "ed-25519-invalid-hash-sha256",
			KeyFile:     "internal/testdata/ed-25519.pem",
			Digest:      testkeys.KnownInputHash(crypto.SHA256),
			Options:     crypto.SHA256,
			ResponseErr: cryptokms.ErrDigestAlgorithm,
		},
		{
			Name:        "ed-25519-sha512-hash-mismatch",
			KeyFile:     "internal/testdata/ed-25519.pem",
			Digest:      testkeys.KnownInputHash(crypto.SHA1),
			ResponseErr: cryptokms.ErrDigestLength,
		},
		{
			Name:    "ed-25519-sha512-pss-options",
			KeyFile: "internal/testdata/ed-25519.pem",
			Digest:  testkeys.KnownInputHash(crypto.SHA512),
			Options: &rsa.PSSOptions{
				Hash:       crypto.SHA512,
				SaltLength: crypto.SHA512.Size(),
			},
			ResponseErr: cryptokms.ErrSignerOpts,
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()
			signer, err := NewSigner(tc.KeyFile)
			if err != nil {
				t.Fatalf("failed to build signer - %s: %s", tc.KeyFile, err)
			}

			signature, err := signer.WithContext(ctx).Sign(
				rand.Reader,
				tc.Digest,
				tc.Options,
			)

			if !errors.Is(err, tc.ResponseErr) {
				t.Fatalf("expected err=%s, got err=%s", tc.ResponseErr, err)
			}

			t.Logf("verifying signature")

			// Verify signature
			if tc.Options == nil {
				tc.Options = signer.HashFunc()
			}

			if tc.ResponseErr == nil {
				err = cryptokms.VerifyDigestSignature(
					signer.Public(),
					tc.Options.HashFunc(),
					tc.Digest, signature)
				if err != nil {
					t.Errorf("signature verification failed: %s", err)
				}
			}
		})
	}
}
