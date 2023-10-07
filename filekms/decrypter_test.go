// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package filekms

import (
	"bytes"
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

func TestWithContext(t *testing.T) {
	s := new(Decrypter)
	ctx := context.Background()
	s = s.WithContext(ctx)

	if ctx != s.ctx {
		t.Fatalf("expected %#v to be %#v", ctx, s.ctx)
	}
}

func TestNewDecrypter(t *testing.T) {
	type testCase struct {
		name      string
		path      string
		decrypter *Decrypter
		ok        bool
	}
	dir := t.TempDir()
	tt := []testCase{
		{
			name: "rsa-1024",
			path: "internal/testdata/rsa-1024.pem",
		},
		{
			name: "rsa-1024.pkcs1",
			path: "internal/testdata/rsa-1024.pkcs1.pem",
		},
		{
			name: "rsa-2048",
			path: "internal/testdata/rsa-2048.pem",
			decrypter: &Decrypter{
				hash:             crypto.SHA256,
				maxCiphertextLen: 2048 / 8,
				algo:             cryptokms.AlgorithmRSA2048,
			},
			ok: true,
		},
		{
			name: "rsa-2048=pkcs1",
			path: "internal/testdata/rsa-2048.pkcs1.pem",
			decrypter: &Decrypter{
				hash:             crypto.SHA256,
				maxCiphertextLen: 2048 / 8,
				algo:             cryptokms.AlgorithmRSA2048,
			},
			ok: true,
		},
		{
			name: "rsa-3072",
			path: "internal/testdata/rsa-3072.pem",
			decrypter: &Decrypter{
				hash:             crypto.SHA256,
				maxCiphertextLen: 3072 / 8,
				algo:             cryptokms.AlgorithmRSA3072,
			},
			ok: true,
		},
		{
			name: "rsa-3072-pkcs1",
			path: "internal/testdata/rsa-3072.pkcs1.pem",
			decrypter: &Decrypter{
				hash:             crypto.SHA256,
				maxCiphertextLen: 3072 / 8,
				algo:             cryptokms.AlgorithmRSA3072,
			},
			ok: true,
		},
		{
			name: "rsa-4096",
			path: "internal/testdata/rsa-4096.pem",
			decrypter: &Decrypter{
				hash:             crypto.SHA256,
				maxCiphertextLen: 4096 / 8,
				algo:             cryptokms.AlgorithmRSA4096,
			},
			ok: true,
		},
		{
			name: "rsa-4096-pkcs1",
			path: "internal/testdata/rsa-4096.pkcs1.pem",
			decrypter: &Decrypter{
				hash:             crypto.SHA256,
				maxCiphertextLen: 4096 / 8,
				algo:             cryptokms.AlgorithmRSA4096,
			},
			ok: true,
		},
		{
			name: "ec-p256",
			path: "internal/testdata/ec-p256.pem",
		},
		{
			name: "ec-p256.ec",
			path: "internal/testdata/ec-p256.ec.pem",
		},
		{
			name: "ec-p384",
			path: "internal/testdata/ec-p384.pem",
		},
		{
			name: "ec-p384.ec",
			path: "internal/testdata/ec-p384.ec.pem",
		},
		{
			name: "ec-p521",
			path: "internal/testdata/ec-p521.pem",
		},
		{
			name: "ec-p521.ec",
			path: "internal/testdata/ec-p521.ec.pem",
		},
		{
			name: "ed-25519",
			path: "internal/testdata/ed-25519.pem",
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
			resp, err := NewDecrypter(tc.path)
			diff := cmp.Diff(
				resp, tc.decrypter,
				cmp.AllowUnexported(Decrypter{}),
				cmpopts.IgnoreFields(Decrypter{}, "mu", "ts", "decrypter", "pub"))

			if tc.ok {
				if err != nil {
					t.Fatalf("expected no error, got: %s", err)
				}

				if diff != "" {
					t.Errorf("did not get expected response: \n%s", diff)
				}

				if resp.Algorithm() != tc.decrypter.algo {
					t.Errorf("expected algo=%d, got=%d",
						tc.decrypter.algo, resp.Algorithm())
				}
				if resp.CreatedAt().IsZero() {
					t.Errorf("expected CreatedAt() to return non zero, got %s",
						resp.CreatedAt())
				}

				if resp.HashFunc() != tc.decrypter.hash {
					t.Errorf("expected HashFunc()=%s, got %s",
						tc.decrypter.hash, resp.HashFunc())
				}
			} else {
				if err == nil {
					t.Errorf("expected error, got nil")
				}

				if resp != nil {
					t.Errorf("decrypter must be nil")
				}
			}
		})
	}
}

func TestDecrypter_Decrypt(t *testing.T) {
	type testCase struct {
		name      string
		ok        bool
		encrypted []byte
		key       string
		opts      crypto.DecrypterOpts
	}
	tt := []testCase{
		{
			name: "valid-rsa-2048-no-options",
			key:  "internal/testdata/rsa-2048.pem",
			ok:   true,
			encrypted: func() []byte {
				decrypter, _ := NewDecrypter("internal/testdata/rsa-2048.pem")
				encrypted, err := rsa.EncryptOAEP(
					decrypter.HashFunc().New(),
					rand.Reader,
					decrypter.Public().(*rsa.PublicKey),
					[]byte(testkeys.KnownInput), nil,
				)
				if err != nil {
					t.Fatalf("failed to encrypt: %s", err)
				}
				return encrypted
			}(),
		},
		{
			name: "valid-rsa-2048-rsa-oaep-sha1",
			key:  "internal/testdata/rsa-2048.pem",
			ok:   true,
			opts: &rsa.OAEPOptions{Hash: crypto.SHA1},
			encrypted: func() []byte {
				decrypter, _ := NewDecrypter("internal/testdata/rsa-2048.pem")
				encrypted, err := rsa.EncryptOAEP(
					crypto.SHA1.New(),
					rand.Reader,
					decrypter.Public().(*rsa.PublicKey),
					[]byte(testkeys.KnownInput), nil,
				)
				if err != nil {
					t.Fatalf("failed to encrypt: %s", err)
				}
				return encrypted
			}(),
		},
		{
			name: "valid-rsa-4096-rsa-oaep-sha256",
			key:  "internal/testdata/rsa-4096.pem",
			ok:   true,
			opts: &rsa.OAEPOptions{Hash: crypto.SHA256},
			encrypted: func() []byte {
				decrypter, _ := NewDecrypter("internal/testdata/rsa-4096.pem")
				encrypted, err := rsa.EncryptOAEP(
					crypto.SHA256.New(),
					rand.Reader,
					decrypter.Public().(*rsa.PublicKey),
					[]byte(testkeys.KnownInput), nil,
				)
				if err != nil {
					t.Fatalf("failed to encrypt: %s", err)
				}
				return encrypted
			}(),
		},
		{
			name: "invalid-rsa-2048-rsa-oaep-sha1-mismatch-mfghash",
			key:  "internal/testdata/rsa-2048.pem",
			opts: &rsa.OAEPOptions{Hash: crypto.SHA1, MGFHash: crypto.SHA256},
			encrypted: func() []byte {
				decrypter, _ := NewDecrypter("internal/testdata/rsa-2048.pem")
				encrypted, err := rsa.EncryptOAEP(
					crypto.SHA1.New(),
					rand.Reader,
					decrypter.Public().(*rsa.PublicKey),
					[]byte(testkeys.KnownInput), nil,
				)
				if err != nil {
					t.Fatalf("failed to encrypt: %s", err)
				}
				return encrypted
			}(),
		},
		{
			name: "rsa-2048-payload-too-large",
			key:  "internal/testdata/rsa-2048.pem",
			opts: &rsa.OAEPOptions{Hash: crypto.SHA1, MGFHash: crypto.SHA1},
			encrypted: func() []byte {
				buf := make([]byte, 8192)
				return buf
			}(),
		},
		{
			name: "invalid-rsa-2048-rsa-PKCS1v15DecryptOptions",
			key:  "internal/testdata/rsa-2048.pem",
			opts: &rsa.PKCS1v15DecryptOptions{},
		},
		{
			name: "invalid-rsa-2048-rsa-decrypter-option",
			key:  "internal/testdata/rsa-2048.pem",
			opts: crypto.SHA1,
		},
		{
			name: "invalid-rsa-2048-hash-mismatch",
			key:  "internal/testdata/rsa-2048.pem",
			opts: &rsa.OAEPOptions{Hash: crypto.SHA1},
			encrypted: func() []byte {
				decrypter, _ := NewDecrypter("internal/testdata/rsa-2048.pem")
				// should be SHA1
				encrypted, err := rsa.EncryptOAEP(
					crypto.SHA256.New(),
					rand.Reader,
					decrypter.Public().(*rsa.PublicKey),
					[]byte(testkeys.KnownInput), nil,
				)
				if err != nil {
					t.Fatalf("failed to encrypt: %s", err)
				}
				return encrypted
			}(),
		},
		{
			name: "invalid-rsa-4096-key-mismatch",
			key:  "internal/testdata/rsa-4096.pem",
			opts: &rsa.OAEPOptions{Hash: crypto.SHA1},
			encrypted: func() []byte {
				decrypter, _ := NewDecrypter("internal/testdata/rsa-2048.pem")
				encrypted, err := rsa.EncryptOAEP(
					crypto.SHA1.New(),
					rand.Reader,
					decrypter.Public().(*rsa.PublicKey),
					[]byte(testkeys.KnownInput), nil,
				)
				if err != nil {
					t.Fatalf("failed to encrypt: %s", err)
				}
				return encrypted
			}(),
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			decrypter, err := NewDecrypter(tc.key)
			if err != nil {
				t.Fatalf("failed to build decrypter: %s", err)
			}

			plaintext, err := decrypter.WithContext(context.Background()).Decrypt(
				rand.Reader,
				tc.encrypted,
				tc.opts,
			)

			if tc.ok {
				if string(plaintext) != testkeys.KnownInput {
					t.Errorf("expected plaintext=%s, got=%s", testkeys.KnownInput, plaintext)
				}
				if err != nil {
					t.Errorf("expected no error, but got: %s", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error, but got nil")
				}
			}
		})
	}
}

func TestDecrypter_Decrypt_Context(t *testing.T) {
	decrypter, err := NewDecrypter("internal/testdata/rsa-3072.pem")
	if err != nil {
		t.Fatalf("failed to build signer: %s", err)
	}

	encrypted, err := rsa.EncryptOAEP(
		decrypter.HashFunc().New(),
		rand.Reader,
		decrypter.Public().(*rsa.PublicKey),
		[]byte(testkeys.KnownInput), nil,
	)
	if err != nil {
		t.Fatalf("failed to encrypt: %s", err)
	}

	t.Run("Cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		plaintext, e1 := decrypter.DecryptContext(ctx, rand.Reader, encrypted, nil)
		if !errors.Is(e1, context.Canceled) {
			t.Errorf("expected error %s but got %s", context.Canceled, e1)
		}
		if plaintext != nil {
			t.Errorf("plaintext must be nil on errors")
		}
	})
	t.Run("Nil", func(t *testing.T) {
		//nolint:staticcheck // ignore for testing.
		plaintext, e2 := decrypter.DecryptContext(nil, rand.Reader, encrypted, &rsa.OAEPOptions{
			Hash: decrypter.HashFunc(),
		})
		if e2 != nil {
			t.Errorf("failed to decrypt: %s", e2)
		}
		if !bytes.Equal(plaintext, []byte(testkeys.KnownInput)) {
			t.Errorf("expected plaintext=%s, got=%s", testkeys.KnownInput, plaintext)
		}
	})
}
