// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package memkms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/tprasadtp/cryptokms"
	"github.com/tprasadtp/cryptokms/internal/shared"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

func TestDecrypter_WithContext(t *testing.T) {
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
		key       []byte
		decrypter *Decrypter
		ok        bool
	}
	tt := []testCase{
		{
			name: "nil",
		},
		{
			name: "rsa-1024-pkcs8",
			key:  shared.MustMarshalPrivateKey(testkeys.GetRSA1024PrivateKey()),
		},
		{
			name: "rsa-1024-pkcs8-base64",
			key: shared.EncodeBase64(
				shared.MustMarshalPrivateKey(testkeys.GetRSA1024PrivateKey()),
			),
		},
		{
			name: "rsa-1024-pkcs1",
			key:  shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA1024PrivateKey()),
		},
		{
			name: "rsa-1024-pkcs1-base64",
			key: shared.EncodeBase64(
				shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA1024PrivateKey()),
			),
		},
		{
			name: "rsa-2048-pkcs8",
			key:  shared.MustMarshalPrivateKey(testkeys.GetRSA2048PrivateKey()),
			decrypter: &Decrypter{
				hash:             crypto.SHA256,
				maxCiphertextLen: 2048 / 8,
				algo:             cryptokms.AlgorithmRSA2048,
			},
			ok: true,
		},
		{
			name: "rsa-2048-pkcs8-base64",
			key: shared.EncodeBase64(
				shared.MustMarshalPrivateKey(testkeys.GetRSA2048PrivateKey()),
			),
			decrypter: &Decrypter{
				hash:             crypto.SHA256,
				maxCiphertextLen: 2048 / 8,
				algo:             cryptokms.AlgorithmRSA2048,
			},
			ok: true,
		},
		{
			name: "rsa-2048-pkcs1",
			key:  shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA2048PrivateKey()),
			decrypter: &Decrypter{
				hash:             crypto.SHA256,
				maxCiphertextLen: 2048 / 8,
				algo:             cryptokms.AlgorithmRSA2048,
			},
			ok: true,
		},
		{
			name: "rsa-2048-pkcs1-base64",
			key:  shared.EncodeBase64(shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA2048PrivateKey())),
			decrypter: &Decrypter{
				hash:             crypto.SHA256,
				maxCiphertextLen: 2048 / 8,
				algo:             cryptokms.AlgorithmRSA2048,
			},
			ok: true,
		},
		{
			name: "rsa-3072-pkcs8",
			key:  shared.MustMarshalPrivateKey(testkeys.GetRSA3072PrivateKey()),
			decrypter: &Decrypter{
				hash:             crypto.SHA256,
				maxCiphertextLen: 3072 / 8,
				algo:             cryptokms.AlgorithmRSA3072,
			},
			ok: true,
		},
		{
			name: "rsa-3072-pkcs8-base64",
			key:  shared.EncodeBase64(shared.MustMarshalPrivateKey(testkeys.GetRSA3072PrivateKey())),
			decrypter: &Decrypter{
				hash:             crypto.SHA256,
				maxCiphertextLen: 3072 / 8,
				algo:             cryptokms.AlgorithmRSA3072,
			},
			ok: true,
		},
		{
			name: "rsa-3072-pkcs1",
			key:  shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA3072PrivateKey()),
			decrypter: &Decrypter{
				hash:             crypto.SHA256,
				maxCiphertextLen: 3072 / 8,
				algo:             cryptokms.AlgorithmRSA3072,
			},
			ok: true,
		},
		{
			name: "rsa-3072-pkcs1-base64",
			key: shared.EncodeBase64(
				shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA3072PrivateKey()),
			),
			decrypter: &Decrypter{
				hash:             crypto.SHA256,
				maxCiphertextLen: 3072 / 8,
				algo:             cryptokms.AlgorithmRSA3072,
			},
			ok: true,
		},
		{
			name: "rsa-4096-pkcs8",
			key:  shared.MustMarshalPrivateKey(testkeys.GetRSA4096PrivateKey()),
			decrypter: &Decrypter{
				hash:             crypto.SHA256,
				maxCiphertextLen: 4096 / 8,
				algo:             cryptokms.AlgorithmRSA4096,
			},
			ok: true,
		},
		{
			name: "rsa-4096-pkcs8-base64",
			key:  shared.EncodeBase64(shared.MustMarshalPrivateKey(testkeys.GetRSA4096PrivateKey())),
			decrypter: &Decrypter{
				hash:             crypto.SHA256,
				maxCiphertextLen: 4096 / 8,
				algo:             cryptokms.AlgorithmRSA4096,
			},
			ok: true,
		},
		{
			name: "rsa-4096-pkcs1",
			key:  shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA4096PrivateKey()),
			decrypter: &Decrypter{
				hash:             crypto.SHA256,
				maxCiphertextLen: 4096 / 8,
				algo:             cryptokms.AlgorithmRSA4096,
			},
			ok: true,
		},
		{
			name: "rsa-4096-pkcs1-base64",
			key:  shared.EncodeBase64(shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA4096PrivateKey())),
			decrypter: &Decrypter{
				hash:             crypto.SHA256,
				maxCiphertextLen: 4096 / 8,
				algo:             cryptokms.AlgorithmRSA4096,
			},
			ok: true,
		},
		{
			name: "invalid-ec-p256",
			key:  shared.MustMarshalPrivateKey(testkeys.GetECP256PrivateKey()),
		},
		{
			name: "invalid-ec-p256.ec",
			key:  shared.MustMarshalECPrivateKey(testkeys.GetECP256PrivateKey()),
		},
		{
			name: "invalid-ec-p384",
			key:  shared.MustMarshalPrivateKey(testkeys.GetECP384PrivateKey()),
		},
		{
			name: "invalid-ec-p384.ec",
			key:  shared.MustMarshalECPrivateKey(testkeys.GetECP384PrivateKey()),
		},
		{
			name: "invalid-ec-p521",
			key:  shared.MustMarshalPrivateKey(testkeys.GetECP521PrivateKey()),
		},
		{
			name: "invalid-ec-p521.ec",
			key:  shared.MustMarshalECPrivateKey(testkeys.GetECP521PrivateKey()),
		},
		{
			name: "invalid-ed25519",
			key:  shared.MustMarshalPrivateKey(testkeys.GetED25519PrivateKey()),
		},
		{
			name: "invalid-rsa-public-key",
			key:  shared.MustMarshalPublicKey(testkeys.GetRSA3072PublicKey()),
		},
		{
			name: "invalid-rsa-public-key-base64",
			key:  shared.EncodeBase64(shared.MustMarshalPublicKey(testkeys.GetRSA3072PublicKey())),
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := NewDecrypter(tc.key)
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
				if !resp.CreatedAt().IsZero() {
					t.Errorf("expected CreatedAt() to return zero, got %s",
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
		key       []byte
		opts      crypto.DecrypterOpts
	}
	tt := []testCase{
		{
			name: "valid-rsa-3072-no-options",
			key:  shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA3072PrivateKey()),
			ok:   true,
			encrypted: func() []byte {
				decrypter, _ := NewDecrypter(
					shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA3072PrivateKey()),
				)
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
			name: "valid-rsa-3072-rsa-oaep-sha1",
			key:  shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA3072PrivateKey()),
			ok:   true,
			opts: &rsa.OAEPOptions{Hash: crypto.SHA1},
			encrypted: func() []byte {
				decrypter, _ := NewDecrypter(
					shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA3072PrivateKey()),
				)
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
			key:  shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA4096PrivateKey()),
			ok:   true,
			opts: &rsa.OAEPOptions{Hash: crypto.SHA256},
			encrypted: func() []byte {
				decrypter, _ := NewDecrypter(
					shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA4096PrivateKey()),
				)
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
			key:  shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA2048PrivateKey()),
			opts: &rsa.OAEPOptions{Hash: crypto.SHA1, MGFHash: crypto.SHA256},
			encrypted: func() []byte {
				decrypter, _ := NewDecrypter(
					shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA2048PrivateKey()),
				)
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
			key:  shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA2048PrivateKey()),
			opts: &rsa.OAEPOptions{Hash: crypto.SHA1, MGFHash: crypto.SHA1},
			encrypted: func() []byte {
				buf := make([]byte, 8192)
				return buf
			}(),
		},
		{
			name: "invalid-rsa-2048-rsa-PKCS1v15DecryptOptions",
			key:  shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA2048PrivateKey()),
			opts: &rsa.PKCS1v15DecryptOptions{},
		},
		{
			name: "invalid-rsa-2048-rsa-decrypter-option",
			key:  shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA2048PrivateKey()),
			opts: crypto.SHA1,
		},
		{
			name: "invalid-rsa-2048-hash-mismatch",
			key:  shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA2048PrivateKey()),
			opts: &rsa.OAEPOptions{Hash: crypto.SHA1},
			encrypted: func() []byte {
				decrypter, _ := NewDecrypter(
					shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA2048PrivateKey()))
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
			key:  shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA4096PrivateKey()),
			opts: &rsa.OAEPOptions{Hash: crypto.SHA1},
			encrypted: func() []byte {
				decrypter, _ := NewDecrypter(
					shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA2048PrivateKey()),
				)
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
	decrypter, err := NewDecrypter(
		shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA3072PrivateKey()),
	)
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
