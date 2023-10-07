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
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/tprasadtp/cryptokms"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

func TestNewSigner(t *testing.T) {
	dir := t.TempDir()
	type testCase struct {
		name   string
		path   string
		signer *Signer
		ok     bool
	}
	tt := []testCase{
		{
			name: "rsa-1024",
			path: "internal/testdata/rsa-1024.pem",
		},
		{
			name: "rsa-1024-pkcs1",
			path: "internal/testdata/rsa-1024.pkcs1.pem",
		},
		{
			name: "rsa-1024-pkcs1-base64-file",
			path: "internal/testdata/rsa-1024.pkcs1.pem.base64",
		},
		{
			name: "rsa-2048",
			path: "internal/testdata/rsa-2048.pem",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA2048,
			},
		},
		{
			name: "rsa-2048-base64",
			path: "internal/testdata/rsa-2048.pem.base64",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA2048,
			},
		},
		{
			name: "rsa-2048-pkcs1",
			path: "internal/testdata/rsa-2048.pkcs1.pem",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA2048,
			},
		},
		{
			name: "rsa-2048-pkcs1-base64",
			path: "internal/testdata/rsa-2048.pkcs1.pem.base64",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA2048,
			},
		},
		{
			name: "rsa-3072",
			path: "internal/testdata/rsa-3072.pem",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA3072,
			},
		},
		{
			name: "rsa-3072-base64",
			path: "internal/testdata/rsa-3072.pem.base64",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA3072,
			},
		},
		{
			name: "rsa-3072-pkcs1",
			path: "internal/testdata/rsa-3072.pkcs1.pem",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA3072,
			},
		},
		{
			name: "rsa-3072-pkcs1-base64",
			path: "internal/testdata/rsa-3072.pkcs1.pem.base64",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA3072,
			},
		},
		{
			name: "rsa-4096",
			path: "internal/testdata/rsa-4096.pem",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA4096,
			},
		},
		{
			name: "rsa-4096-base64",
			path: "internal/testdata/rsa-4096.pem.base64",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA4096,
			},
		},
		{
			name: "rsa-4096-pkcs1",
			path: "internal/testdata/rsa-4096.pkcs1.pem",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA4096,
			},
		},
		{
			name: "rsa-4096-pkcs1-base64",
			path: "internal/testdata/rsa-4096.pkcs1.pem.base64",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA4096,
			},
		},
		// EC-P224
		{
			name: "ec-p224",
			path: "internal/testdata/ec-p224.pem",
		},
		{
			name: "ec-p224-base64",
			path: "internal/testdata/ec-p224.pem.base64",
		},
		{
			name: "ec-p224.ec",
			path: "internal/testdata/ec-p224.ec.pem",
		},
		{
			name: "ec-p224.ec-base64",
			path: "internal/testdata/ec-p224.ec.pem.base64",
		},
		// EC-P256
		{
			name: "ec-p256",
			path: "internal/testdata/ec-p256.pem",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmECP256,
			},
		},
		{
			name: "ec-p256-base64",
			path: "internal/testdata/ec-p256.pem.base64",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmECP256,
			},
		},
		{
			name: "ec-p256.ec",
			path: "internal/testdata/ec-p256.ec.pem",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmECP256,
			},
		},
		{
			name: "ec-p256.ec-base64",
			path: "internal/testdata/ec-p256.ec.pem.base64",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmECP256,
			},
		},
		{
			name: "ec-p384",
			path: "internal/testdata/ec-p384.pem",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA384,
				algo: cryptokms.AlgorithmECP384,
			},
		},
		{
			name: "ec-p384-base64",
			path: "internal/testdata/ec-p384.pem.base64",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA384,
				algo: cryptokms.AlgorithmECP384,
			},
		},
		{
			name: "ec-p384.ec",
			path: "internal/testdata/ec-p384.ec.pem",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA384,
				algo: cryptokms.AlgorithmECP384,
			},
		},
		{
			name: "ec-p384.ec-base64",
			path: "internal/testdata/ec-p384.ec.pem.base64",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA384,
				algo: cryptokms.AlgorithmECP384,
			},
		},
		{
			name: "ec-p521",
			path: "internal/testdata/ec-p521.pem",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA512,
				algo: cryptokms.AlgorithmECP521,
			},
		},
		{
			name: "ec-p521-base64",
			path: "internal/testdata/ec-p521.pem.base64",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA512,
				algo: cryptokms.AlgorithmECP521,
			},
		},
		{
			name: "ec-p521.ec",
			path: "internal/testdata/ec-p521.ec.pem",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA512,
				algo: cryptokms.AlgorithmECP521,
			},
		},
		{
			name: "ec-p521.ec-base64",
			path: "internal/testdata/ec-p521.ec.pem.base64",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA512,
				algo: cryptokms.AlgorithmECP521,
			},
		},
		{
			name: "ed-25519",
			path: "internal/testdata/ed-25519.pem",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA512,
				algo: cryptokms.AlgorithmED25519,
			},
		},
		{
			name: "ed-25519-base64",
			path: "internal/testdata/ed-25519.pem.base64",
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA512,
				algo: cryptokms.AlgorithmED25519,
			},
		},
		{
			name: "non-existing-file",
			path: filepath.Join(dir, "non-existing-file.pem"),
		},
		{
			name: "not-a-file",
			path: dir,
		},
		{
			name: "empty-file",
			path: "internal/testdata/.gitkeep",
		},
		{
			name: "public-key-file",
			path: "../gcpkms/internal/testdata/rsa-sign-pkcs1-4096-sha512.pub",
		},
		{
			name: "file-size-too-large",
			path: func() string {
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
		t.Run(tc.name, func(t *testing.T) {
			resp, err := NewSigner(tc.path)
			if tc.ok {
				diff := cmp.Diff(
					resp, tc.signer,
					cmp.AllowUnexported(Signer{}),
					cmpopts.IgnoreFields(Signer{}, "mu", "signer", "pub", "ts"))

				if diff != "" {
					t.Errorf("did not get expected response: \n%s", diff)
				}

				if resp.Algorithm() != tc.signer.algo {
					t.Errorf("expected algo=%d, got=%d", tc.signer.algo, resp.Algorithm())
				}
				if resp.CreatedAt().IsZero() {
					t.Errorf("expected CreatedAt() to return non zero, got %s", resp.CreatedAt())
				}
				if resp.HashFunc() != tc.signer.hash {
					t.Errorf("expected HashFunc()=%s, got %s", tc.signer.hash, resp.HashFunc())
				}
			} else {
				if err == nil {
					t.Errorf("expected error, got nil")
				}

				if resp != nil {
					t.Errorf("expected signer to be nil, got %#v", resp)
				}
			}
		})
	}
}

func TestSigner_Sign(t *testing.T) {
	type testCase struct {
		name   string
		file   string
		digest []byte
		opts   crypto.SignerOpts
		ok     bool
	}
	tt := []testCase{
		{
			name:   "rsa-2048-default-hash",
			file:   "internal/testdata/rsa-2048.pem",
			digest: testkeys.KnownInputHash(crypto.SHA256),
			ok:     true,
		},
		{
			name:   "rsa-2048-with-sha-256",
			file:   "internal/testdata/rsa-2048.pem",
			digest: testkeys.KnownInputHash(crypto.SHA256),
			opts:   crypto.SHA256,
			ok:     true,
		},
		{
			name:   "rsa-2048-with-sha-384",
			file:   "internal/testdata/rsa-2048.pem",
			digest: testkeys.KnownInputHash(crypto.SHA384),
			opts:   crypto.SHA384,
			ok:     true,
		},
		{
			name:   "rsa-2048-with-sha-512",
			file:   "internal/testdata/rsa-2048.pem",
			digest: testkeys.KnownInputHash(crypto.SHA512),
			opts:   crypto.SHA512,
			ok:     true,
		},
		{
			name:   "rsa-2048-with-sha-512-invalid-hash",
			file:   "internal/testdata/rsa-2048.pem",
			digest: testkeys.KnownInputHash(crypto.SHA1),
			opts:   crypto.SHA512,
		},
		{
			name:   "rsa-2048-with-pss-options-empty",
			file:   "internal/testdata/rsa-2048.pem",
			digest: testkeys.KnownInputHash(crypto.SHA256),
			opts:   &rsa.PSSOptions{},
			ok:     true,
		},
		{
			name:   "rsa-2048-with-pss-options-hash-only",
			file:   "internal/testdata/rsa-2048.pem",
			digest: testkeys.KnownInputHash(crypto.SHA256),
			opts:   &rsa.PSSOptions{Hash: crypto.SHA256},
			ok:     true,
		},
		{
			name:   "rsa-2048-with-pss-options-hash-and-saltlen",
			file:   "internal/testdata/rsa-2048.pem",
			digest: testkeys.KnownInputHash(crypto.SHA256),
			opts: &rsa.PSSOptions{
				Hash:       crypto.SHA256,
				SaltLength: crypto.SHA256.HashFunc().Size(),
			},
			ok: true,
		},
		{
			name:   "rsa-2048-with-pss-options-hash-and-saltlen-mismatch",
			file:   "internal/testdata/rsa-2048.pem",
			digest: testkeys.KnownInputHash(crypto.SHA256),
			opts: &rsa.PSSOptions{
				Hash:       crypto.SHA256,
				SaltLength: crypto.SHA512.HashFunc().Size(),
			},
		},
		{
			name:   "rsa-2048-with-pss-options-hash-len-mismatch",
			file:   "internal/testdata/rsa-2048.pem",
			digest: testkeys.KnownInputHash(crypto.SHA1),
			opts: &rsa.PSSOptions{
				Hash: crypto.SHA256,
			},
		},
		// P-256
		{
			name:   "ec-p256-default",
			file:   "internal/testdata/ec-p256.pem",
			digest: testkeys.KnownInputHash(crypto.SHA256),
			ok:     true,
		},
		{
			name:   "ec-p256-sha256",
			file:   "internal/testdata/ec-p256.pem",
			digest: testkeys.KnownInputHash(crypto.SHA256),
			opts:   crypto.SHA256,
			ok:     true,
		},
		{
			name:   "ec-p256-invalid-hash-sha512",
			file:   "internal/testdata/ec-p256.pem",
			digest: testkeys.KnownInputHash(crypto.SHA512),
			opts:   crypto.SHA512,
		},
		{
			name:   "ec-p256-sha256-hash-mismatch",
			file:   "internal/testdata/ec-p256.pem",
			digest: testkeys.KnownInputHash(crypto.SHA1),
			opts:   crypto.SHA256,
		},
		{
			name:   "ec-p256-sha256-pss-options",
			file:   "internal/testdata/ec-p256.pem",
			digest: testkeys.KnownInputHash(crypto.SHA256),
			opts: &rsa.PSSOptions{
				Hash:       crypto.SHA256,
				SaltLength: crypto.SHA256.Size(),
			},
		},
		// P384
		{
			name:   "ec-p384",
			file:   "internal/testdata/ec-p384.pem",
			digest: testkeys.KnownInputHash(crypto.SHA384),
			ok:     true,
		},
		{
			name:   "ec-p384-sha384",
			file:   "internal/testdata/ec-p384.pem",
			digest: testkeys.KnownInputHash(crypto.SHA384),
			opts:   crypto.SHA384,
			ok:     true,
		},
		{
			name:   "ec-p384-invalid-hash-sha512",
			file:   "internal/testdata/ec-p384.pem",
			digest: testkeys.KnownInputHash(crypto.SHA512),
			opts:   crypto.SHA512,
		},
		{
			name:   "ec-p384-sha384-hash-mismatch",
			file:   "internal/testdata/ec-p384.pem",
			digest: testkeys.KnownInputHash(crypto.SHA1),
		},
		{
			name:   "ec-p384-sha384-pss-options",
			file:   "internal/testdata/ec-p384.pem",
			digest: testkeys.KnownInputHash(crypto.SHA384),
			opts: &rsa.PSSOptions{
				Hash:       crypto.SHA384,
				SaltLength: crypto.SHA384.Size(),
			},
		},
		// P521
		{
			name:   "ec-p521",
			file:   "internal/testdata/ec-p521.pem",
			digest: testkeys.KnownInputHash(crypto.SHA512),
			ok:     true,
		},
		{
			name:   "ec-p521-sha512",
			file:   "internal/testdata/ec-p521.pem",
			digest: testkeys.KnownInputHash(crypto.SHA512),
			opts:   crypto.SHA512,
			ok:     true,
		},
		{
			name:   "ec-p521-invalid-hash-sha256",
			file:   "internal/testdata/ec-p521.pem",
			digest: testkeys.KnownInputHash(crypto.SHA256),
			opts:   crypto.SHA256,
		},
		{
			name:   "ec-p521-sha521-hash-mismatch",
			file:   "internal/testdata/ec-p521.pem",
			digest: testkeys.KnownInputHash(crypto.SHA1),
		},
		{
			name:   "ec-p521-sha521-pss-options",
			file:   "internal/testdata/ec-p521.pem",
			digest: testkeys.KnownInputHash(crypto.SHA512),
			opts: &rsa.PSSOptions{
				Hash:       crypto.SHA512,
				SaltLength: crypto.SHA512.Size(),
			},
		},
		// ED25529
		{
			name:   "ed-25519",
			file:   "internal/testdata/ed-25519.pem",
			digest: testkeys.KnownInputHash(crypto.SHA512),
			ok:     true,
		},
		{
			name:   "ed-25519-sha512",
			file:   "internal/testdata/ed-25519.pem",
			digest: testkeys.KnownInputHash(crypto.SHA512),
			opts:   crypto.SHA512,
			ok:     true,
		},
		{
			name:   "ed-25519-invalid-hash-sha256",
			file:   "internal/testdata/ed-25519.pem",
			digest: testkeys.KnownInputHash(crypto.SHA256),
			opts:   crypto.SHA256,
		},
		{
			name:   "ed-25519-sha512-hash-mismatch",
			file:   "internal/testdata/ed-25519.pem",
			digest: testkeys.KnownInputHash(crypto.SHA1),
		},
		{
			name:   "ed-25519-sha512-pss-options",
			file:   "internal/testdata/ed-25519.pem",
			digest: testkeys.KnownInputHash(crypto.SHA512),
			opts: &rsa.PSSOptions{
				Hash:       crypto.SHA512,
				SaltLength: crypto.SHA512.Size(),
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			signer, err := NewSigner(tc.file)
			if err != nil {
				t.Fatalf("failed to build signer - %s: %s", tc.file, err)
			}

			signature, err := signer.WithContext(ctx).Sign(
				rand.Reader,
				tc.digest,
				tc.opts,
			)

			if tc.ok {
				if err != nil {
					t.Fatalf("expected no error got: %s", err)
				}

				if tc.opts == nil {
					tc.opts = signer.HashFunc()
				}
				err = cryptokms.VerifyDigestSignature(
					signer.Public(),
					tc.opts.HashFunc(),
					tc.digest, signature)
				if err != nil {
					t.Errorf("signature verification failed: %s", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error, got nil")
				}

				if signature != nil {
					t.Errorf("signature must be on error")
				}
			}
		})
	}
}

func TestSigner_Sign_Context(t *testing.T) {
	signer, err := NewSigner("internal/testdata/ec-p256.pem")
	if err != nil {
		t.Fatalf("failed to build signer: %s", err)
	}

	t.Run("Cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		signature, e1 := signer.SignContext(ctx, rand.Reader, testkeys.KnownInputHash(crypto.SHA256), nil)
		if !errors.Is(e1, context.Canceled) {
			t.Errorf("expected error %s but got %s", context.Canceled, e1)
		}
		if signature != nil {
			t.Errorf("signature must be nil on errors")
		}
	})
	t.Run("Nil", func(t *testing.T) {
		digest := testkeys.KnownInputHash(crypto.SHA256)
		//nolint:staticcheck // ignore for testing.
		signature, e2 := signer.SignContext(nil, rand.Reader, digest, nil)
		if e2 != nil {
			t.Errorf("failed to decrypt: %s", e2)
		}

		err = cryptokms.VerifySignature(
			signer.Public(),
			signer.HashFunc(),
			strings.NewReader(testkeys.KnownInput),
			signature)
		if err != nil {
			t.Errorf("signature verification failed: %s", err)
		}
	})
}
