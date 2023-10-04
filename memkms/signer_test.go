// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package memkms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/tprasadtp/cryptokms"
	"github.com/tprasadtp/cryptokms/internal/shared"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

func TestNewSigner(t *testing.T) {
	type testCase struct {
		name   string
		key    []byte
		signer *Signer
		ok     bool
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
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA2048,
			},
			ok: true,
		},
		{
			name: "rsa-2048-pkcs8-base64",
			key: shared.EncodeBase64(
				shared.MustMarshalPrivateKey(testkeys.GetRSA2048PrivateKey()),
			),
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA2048,
			},
			ok: true,
		},
		{
			name: "rsa-2048-pkcs1",
			key:  shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA2048PrivateKey()),
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA2048,
			},
			ok: true,
		},
		{
			name: "rsa-2048-pkcs1-base64",
			key:  shared.EncodeBase64(shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA2048PrivateKey())),
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA2048,
			},
			ok: true,
		},
		{
			name: "rsa-3072-pkcs8",
			key:  shared.MustMarshalPrivateKey(testkeys.GetRSA3072PrivateKey()),
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA3072,
			},
			ok: true,
		},
		{
			name: "rsa-3072-pkcs8-base64",
			key:  shared.EncodeBase64(shared.MustMarshalPrivateKey(testkeys.GetRSA3072PrivateKey())),
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA3072,
			},
			ok: true,
		},
		{
			name: "rsa-3072-pkcs1",
			key:  shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA3072PrivateKey()),
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA3072,
			},
			ok: true,
		},
		{
			name: "rsa-3072-pkcs1-base64",
			key: shared.EncodeBase64(
				shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA3072PrivateKey()),
			),
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA3072,
			},
			ok: true,
		},
		{
			name: "rsa-4096-pkcs8",
			key:  shared.MustMarshalPrivateKey(testkeys.GetRSA4096PrivateKey()),
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA4096,
			},
			ok: true,
		},
		{
			name: "rsa-4096-pkcs8-base64",
			key:  shared.EncodeBase64(shared.MustMarshalPrivateKey(testkeys.GetRSA4096PrivateKey())),
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA4096,
			},
			ok: true,
		},
		{
			name: "rsa-4096-pkcs1",
			key:  shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA4096PrivateKey()),
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA4096,
			},
			ok: true,
		},
		{
			name: "rsa-4096-pkcs1-base64",
			key:  shared.EncodeBase64(shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA4096PrivateKey())),
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmRSA4096,
			},
			ok: true,
		},

		{
			name: "ec-p256-pkcs8",
			key:  shared.MustMarshalPrivateKey(testkeys.GetECP256PrivateKey()),
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmECP256,
			},
		},
		{
			name: "ec-p256-pkcs8-base64",
			key:  shared.EncodeBase64(shared.MustMarshalPrivateKey(testkeys.GetECP256PrivateKey())),
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmECP256,
			},
		},
		{
			name: "ec-p256.ec",
			key:  shared.MustMarshalECPrivateKey(testkeys.GetECP256PrivateKey()),
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmECP256,
			},
		},
		{
			name: "ec-p256.ec-base64",
			key:  shared.EncodeBase64(shared.MustMarshalECPrivateKey(testkeys.GetECP256PrivateKey())),
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA256,
				algo: cryptokms.AlgorithmECP256,
			},
		},
		// ECDSA-P384
		{
			name: "ec-p384-pkcs8",
			key:  shared.MustMarshalPrivateKey(testkeys.GetECP384PrivateKey()),
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA384,
				algo: cryptokms.AlgorithmECP384,
			},
		},
		{
			name: "ec-p384-pkcs8-base64",
			key:  shared.EncodeBase64(shared.MustMarshalPrivateKey(testkeys.GetECP384PrivateKey())),
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA384,
				algo: cryptokms.AlgorithmECP384,
			},
		},
		{
			name: "ec-p384.ec",
			key:  shared.MustMarshalECPrivateKey(testkeys.GetECP384PrivateKey()),
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA384,
				algo: cryptokms.AlgorithmECP384,
			},
		},
		{
			name: "ec-p384.ec-base64",
			key:  shared.EncodeBase64(shared.MustMarshalECPrivateKey(testkeys.GetECP384PrivateKey())),
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA384,
				algo: cryptokms.AlgorithmECP384,
			},
		},
		// ECDSA-P521
		{
			name: "ec-p521-pkcs8",
			key:  shared.MustMarshalPrivateKey(testkeys.GetECP521PrivateKey()),
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA512,
				algo: cryptokms.AlgorithmECP521,
			},
		},
		{
			name: "ec-p521-pkcs8-base64",
			key:  shared.EncodeBase64(shared.MustMarshalPrivateKey(testkeys.GetECP521PrivateKey())),
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA512,
				algo: cryptokms.AlgorithmECP521,
			},
		},
		{
			name: "ec-p521.ec",
			key:  shared.MustMarshalECPrivateKey(testkeys.GetECP521PrivateKey()),
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA512,
				algo: cryptokms.AlgorithmECP521,
			},
		},
		{
			name: "ec-p521.ec-base64",
			key:  shared.EncodeBase64(shared.MustMarshalECPrivateKey(testkeys.GetECP521PrivateKey())),
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA512,
				algo: cryptokms.AlgorithmECP521,
			},
		},
		{
			name: "ed-25519",
			key:  shared.MustMarshalPrivateKey(testkeys.GetED25519PrivateKey()),
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA512,
				algo: cryptokms.AlgorithmED25519,
			},
		},
		{
			name: "ed-25519-base64",
			key:  shared.EncodeBase64(shared.MustMarshalPrivateKey(testkeys.GetED25519PrivateKey())),
			ok:   true,
			signer: &Signer{
				hash: crypto.SHA512,
				algo: cryptokms.AlgorithmED25519,
			},
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
			resp, err := NewSigner(tc.key)
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
				if !resp.CreatedAt().IsZero() {
					t.Errorf("expected CreatedAt() to return zero, got %s", resp.CreatedAt())
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
		key    []byte
		digest []byte
		opts   crypto.SignerOpts
		ok     bool
	}
	tt := []testCase{
		{
			name:   "rsa-2048-default-hash",
			key:    shared.MustMarshalPrivateKey(testkeys.GetRSA2048PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			ok:     true,
		},
		{
			name:   "rsa-2048-with-sha-256",
			key:    shared.MustMarshalPrivateKey(testkeys.GetRSA2048PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			opts:   crypto.SHA256,
			ok:     true,
		},
		{
			name:   "rsa-2048-with-sha-384",
			key:    shared.MustMarshalPrivateKey(testkeys.GetRSA2048PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA384),
			opts:   crypto.SHA384,
			ok:     true,
		},
		{
			name:   "rsa-2048-with-sha-512",
			key:    shared.MustMarshalPrivateKey(testkeys.GetRSA2048PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA512),
			opts:   crypto.SHA512,
			ok:     true,
		},
		{
			name:   "rsa-2048-with-sha-512-invalid-hash",
			key:    shared.MustMarshalPrivateKey(testkeys.GetRSA2048PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA1),
			opts:   crypto.SHA512,
		},
		{
			name:   "rsa-2048-with-pss-options-empty",
			key:    shared.MustMarshalPrivateKey(testkeys.GetRSA2048PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			opts:   &rsa.PSSOptions{},
			ok:     true,
		},
		{
			name:   "rsa-2048-with-pss-options-hash-only",
			key:    shared.MustMarshalPrivateKey(testkeys.GetRSA2048PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			opts:   &rsa.PSSOptions{Hash: crypto.SHA256},
			ok:     true,
		},
		{
			name:   "rsa-2048-with-pss-options-hash-and-saltlen",
			key:    shared.MustMarshalPrivateKey(testkeys.GetRSA2048PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			opts: &rsa.PSSOptions{
				Hash:       crypto.SHA256,
				SaltLength: crypto.SHA256.HashFunc().Size(),
			},
			ok: true,
		},
		{
			name:   "rsa-2048-with-pss-options-hash-and-saltlen-mismatch",
			key:    shared.MustMarshalPrivateKey(testkeys.GetRSA2048PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			opts: &rsa.PSSOptions{
				Hash:       crypto.SHA256,
				SaltLength: crypto.SHA512.HashFunc().Size(),
			},
		},
		{
			name:   "rsa-2048-with-pss-options-hash-len-mismatch",
			key:    shared.MustMarshalPrivateKey(testkeys.GetRSA2048PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA1),
			opts: &rsa.PSSOptions{
				Hash: crypto.SHA256,
			},
		},
		// P-256
		{
			name:   "ec-p256-default",
			key:    shared.MustMarshalPrivateKey(testkeys.GetECP256PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			ok:     true,
		},
		{
			name:   "ec-p256-sha256",
			key:    shared.MustMarshalPrivateKey(testkeys.GetECP256PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			opts:   crypto.SHA256,
			ok:     true,
		},
		{
			name:   "ec-p256-invalid-hash-sha512",
			key:    shared.MustMarshalPrivateKey(testkeys.GetECP256PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA512),
			opts:   crypto.SHA512,
		},
		{
			name:   "ec-p256-sha256-hash-mismatch",
			key:    shared.MustMarshalPrivateKey(testkeys.GetECP256PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA1),
			opts:   crypto.SHA256,
		},
		{
			name:   "ec-p256-sha256-pss-options",
			key:    shared.MustMarshalPrivateKey(testkeys.GetECP256PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			opts: &rsa.PSSOptions{
				Hash:       crypto.SHA256,
				SaltLength: crypto.SHA256.Size(),
			},
		},
		// P384
		{
			name:   "ec-p384",
			key:    shared.MustMarshalPrivateKey(testkeys.GetECP384PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA384),
			ok:     true,
		},
		{
			name:   "ec-p384-sha384",
			key:    shared.MustMarshalPrivateKey(testkeys.GetECP384PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA384),
			opts:   crypto.SHA384,
			ok:     true,
		},
		{
			name:   "ec-p384-invalid-hash-sha512",
			key:    shared.MustMarshalPrivateKey(testkeys.GetECP384PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA512),
			opts:   crypto.SHA512,
		},
		{
			name:   "ec-p384-sha384-hash-mismatch",
			key:    shared.MustMarshalPrivateKey(testkeys.GetECP384PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA1),
		},
		{
			name:   "ec-p384-sha384-pss-options",
			key:    shared.MustMarshalPrivateKey(testkeys.GetECP384PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA384),
			opts: &rsa.PSSOptions{
				Hash:       crypto.SHA384,
				SaltLength: crypto.SHA384.Size(),
			},
		},
		// P521
		{
			name:   "ec-p521",
			key:    shared.MustMarshalPrivateKey(testkeys.GetECP521PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA512),
			ok:     true,
		},
		{
			name:   "ec-p521-sha512",
			key:    shared.MustMarshalPrivateKey(testkeys.GetECP521PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA512),
			opts:   crypto.SHA512,
			ok:     true,
		},
		{
			name:   "ec-p521-invalid-hash-sha256",
			key:    shared.MustMarshalPrivateKey(testkeys.GetECP521PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			opts:   crypto.SHA256,
		},
		{
			name:   "ec-p521-SHA512-hash-mismatch",
			key:    shared.MustMarshalPrivateKey(testkeys.GetECP521PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA1),
		},
		{
			name:   "ec-p521-SHA512-pss-options",
			key:    shared.MustMarshalPrivateKey(testkeys.GetECP521PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA512),
			opts: &rsa.PSSOptions{
				Hash:       crypto.SHA512,
				SaltLength: crypto.SHA512.Size(),
			},
		},
		// ED25529
		{
			name:   "ed-25519",
			key:    shared.MustMarshalPrivateKey(testkeys.GetED25519PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA512),
			ok:     true,
		},
		{
			name:   "ed-25519-sha512",
			key:    shared.MustMarshalPrivateKey(testkeys.GetED25519PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA512),
			opts:   crypto.SHA512,
			ok:     true,
		},
		{
			name:   "ed-25519-invalid-hash-sha256",
			key:    shared.MustMarshalPrivateKey(testkeys.GetED25519PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA256),
			opts:   crypto.SHA256,
		},
		{
			name:   "ed-25519-sha512-hash-mismatch",
			key:    shared.MustMarshalPrivateKey(testkeys.GetED25519PrivateKey()),
			digest: testkeys.KnownInputHash(crypto.SHA1),
		},
		{
			name:   "ed-25519-sha512-pss-options",
			key:    shared.MustMarshalPrivateKey(testkeys.GetED25519PrivateKey()),
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
			signer, err := NewSigner(tc.key)
			if err != nil {
				t.Fatalf("failed to build signer - %s: %s", tc.key, err)
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
	signer, err := NewSigner(shared.MustMarshalPrivateKey(testkeys.GetECP256PrivateKey()))
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
