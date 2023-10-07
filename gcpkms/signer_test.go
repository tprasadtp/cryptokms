// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package gcpkms

import (
	"context"
	"crypto"
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/tprasadtp/cryptokms"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

func TestNewSigner(t *testing.T) {
	type testCase struct {
		name   string
		key    string
		signer *Signer
		ok     bool
	}

	server := newFakeServer(t)
	server.Serve(t)
	clientOptions := server.Options(t)

	tt := []testCase{
		{
			name: "force-error-response-on-GetCryptoKeyVersion",
			key:  "ERROR_GET_CRYPTOKEY_VERSION",
		},
		{
			name: "destroyed-key",
			key:  "DESTROYED_RSA_SIGN_PKCS1_2048_SHA256",
		},
		{
			name: "unsupported-key-secp256k1",
			key:  "EC_SIGN_SECP256K1_SHA256",
		},
		// HMAC Keys
		{
			name: "unsupported-key-hmac-sha1",
			key:  "HMAC_SHA1",
		},
		{
			name: "unsupported-key-hmac-sha224",
			key:  "HMAC_SHA224",
		},
		{
			name: "unsupported-key-hmac-sha256",
			key:  "HMAC_SHA256",
		},
		{
			name: "unsupported-key-hmac-sha384",
			key:  "HMAC_SHA384",
		},
		{
			name: "unsupported-key-hmac-sha512",
			key:  "HMAC_SHA512",
		},
		// symmetric keys
		{
			name: "unsupported-key-google-symmetric",
			key:  "GOOGLE_SYMMETRIC_ENCRYPTION",
		},
		{
			name: "unsupported-key-encryption-rsa2048-sha1",
			key:  "RSA_DECRYPT_OAEP_2048_SHA1",
		},
		{
			name: "unsupported-key-encryption-rsa3072-sha1",
			key:  "RSA_DECRYPT_OAEP_3072_SHA1",
		},
		{
			name: "unsupported-key-encryption-rsa4096-sha1",
			key:  "RSA_DECRYPT_OAEP_4096_SHA1",
		},
		// SHA256
		{
			name: "unsupported-key-encryption-rsa2048-sha256",
			key:  "RSA_DECRYPT_OAEP_2048_SHA256",
		},
		{
			name: "unsupported-key-encryption-rsa3072-sha256",
			key:  "RSA_DECRYPT_OAEP_3072_SHA256",
		},
		{
			name: "unsupported-key-encryption-rsa4096-sha256",
			key:  "RSA_DECRYPT_OAEP_4096_SHA256",
		},
		{
			name: "unsupported-key-encryption-rsa4096-sha512",
			key:  "RSA_DECRYPT_OAEP_4096_SHA512",
		},
		// unknown key
		{
			name: "unsupported-key-external-symmetric-encryption",
			key:  "EXTERNAL_SYMMETRIC_ENCRYPTION",
		},
		{
			name: "error-srv-rsa-pss-2048-sha256",
			key:  "RSA_SIGN_PSS_2048_SHA256",
		},
		{
			name: "error-srv-rsa-pss-3072-sha256",
			key:  "RSA_SIGN_PSS_3072_SHA256",
		},
		{
			name: "error-srv-rsa-pss-4096-sha256",
			key:  "RSA_SIGN_PSS_4096_SHA256",
		},
		{
			name: "error-srv-rsa-pss-4096-sha512",
			key:  "RSA_SIGN_PSS_4096_SHA512",
		},
		// get key corrupted response
		{
			name: "integrity-invalid-rsa-sign-pkcs1-2048-sha256",
			key:  "ERROR_SRV_INTEGRITY_RSA_SIGN_PKCS1_2048_SHA256",
		},
		{
			name: "integrity-invalid-rsa-sign-pkcs1-3072-sha256",
			key:  "ERROR_SRV_INTEGRITY_RSA_SIGN_PKCS1_3072_SHA256",
		},
		{
			name: "integrity-invalid-rsa-sign-pkcs1-4096-sha256",
			key:  "ERROR_SRV_INTEGRITY_RSA_SIGN_PKCS1_4096_SHA256",
		},
		{
			name: "integrity-invalid-rsa-sign-pkcs1-4096-sha512",
			key:  "ERROR_SRV_INTEGRITY_RSA_SIGN_PKCS1_4096_SHA512",
		},
		{
			name: "integrity-invalid-ec-sign-p256-sha256",
			key:  "ERROR_SRV_INTEGRITY_EC_SIGN_P256_SHA256",
		},
		{
			name: "integrity-invalid-ec-sign-p384-sha384",
			key:  "ERROR_SRV_INTEGRITY_EC_SIGN_P384_SHA384",
		},
		// GetPublicKey returns an error.
		{
			name: "error-on-GetPublicKey",
			key:  "ERROR_ON_GET_PUBLICKEY_EC_SIGN_P256_SHA256",
		},
		// Returns RSA Signer
		{
			name: "valid-RSA_SIGN_PKCS1_2048_SHA256",
			key:  "RSA_SIGN_PKCS1_2048_SHA256",
			ok:   true,
			signer: &Signer{
				name:  "RSA_SIGN_PKCS1_2048_SHA256",
				hash:  crypto.SHA256,
				ctime: knownTS,
				pub:   &testkeys.GetRSA2048PrivateKey().PublicKey,
				algo:  cryptokms.AlgorithmRSA2048,
			},
		},
		{
			name: "valid-RSA_SIGN_PKCS1_3072_SHA256",
			key:  "RSA_SIGN_PKCS1_3072_SHA256",
			ok:   true,
			signer: &Signer{
				name:  "RSA_SIGN_PKCS1_3072_SHA256",
				hash:  crypto.SHA256,
				ctime: knownTS,
				pub:   &testkeys.GetRSA3072PrivateKey().PublicKey,
				algo:  cryptokms.AlgorithmRSA3072,
			},
		},
		{
			name: "valid-RSA_SIGN_PKCS1_4096_SHA256",
			key:  "RSA_SIGN_PKCS1_4096_SHA256",
			ok:   true,
			signer: &Signer{
				name:  "RSA_SIGN_PKCS1_4096_SHA256",
				hash:  crypto.SHA256,
				ctime: knownTS,
				pub:   &testkeys.GetRSA4096PrivateKey().PublicKey,
				algo:  cryptokms.AlgorithmRSA4096,
			},
		},
		{
			name: "valid-RSA_SIGN_PKCS1_4096_SHA512",
			key:  "RSA_SIGN_PKCS1_4096_SHA512",
			ok:   true,
			signer: &Signer{
				name:  "RSA_SIGN_PKCS1_4096_SHA512",
				hash:  crypto.SHA512,
				ctime: knownTS,
				pub:   &testkeys.GetRSA4096PrivateKey().PublicKey,
				algo:  cryptokms.AlgorithmRSA4096,
			},
		},
		{
			name: "valid-EC_SIGN_P256_SHA256",
			key:  "EC_SIGN_P256_SHA256",
			ok:   true,
			signer: &Signer{
				name:  "EC_SIGN_P256_SHA256",
				hash:  crypto.SHA256,
				ctime: knownTS,
				pub:   &testkeys.GetECP256PrivateKey().PublicKey,
				algo:  cryptokms.AlgorithmECP256,
			},
		},
		{
			name: "valid-EC_SIGN_P384_SHA384",
			key:  "EC_SIGN_P384_SHA384",
			ok:   true,
			signer: &Signer{
				name:  "EC_SIGN_P384_SHA384",
				hash:  crypto.SHA384,
				ctime: knownTS,
				pub:   &testkeys.GetECP384PrivateKey().PublicKey,
				algo:  cryptokms.AlgorithmECP384,
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			resp, err := NewSigner(ctx, tc.key, clientOptions...)
			diff := cmp.Diff(
				resp, tc.signer,
				cmp.AllowUnexported(Signer{}),
				cmpopts.IgnoreFields(Signer{}, "client", "mu"))
			if diff != "" {
				t.Errorf("did not get expected response: \n%s", diff)
			}

			if tc.ok {
				if err != nil {
					t.Errorf("expected no error, but got %s", err)
				}
				if resp.Algorithm() != tc.signer.algo {
					t.Errorf("expected algo=%d, got=%d", tc.signer.algo, resp.Algorithm())
				}
			} else {
				if err == nil {
					t.Errorf("expected an error, got nil")
				}
			}
		})
	}
}

func Test_Signer_Sign_UnInitialized(t *testing.T) {
	signer := &Signer{}
	_, err := signer.Sign(
		rand.Reader,
		testkeys.KnownInputHash(crypto.SHA256),
		crypto.SHA256,
	)

	if err == nil {
		t.Errorf("expected error when calling Sign on un initialized client")
	}
}

func Test_Signer_WithContext(t *testing.T) {
	s := new(Signer)
	ctx := context.Background()
	s = s.WithContext(ctx)

	if !reflect.DeepEqual(ctx, s.ctx) {
		t.Fatalf("expected %#v to be %#v", ctx, s.ctx)
	}
}

func Test_Signer_Sign(t *testing.T) {
	type testCase struct {
		name   string
		digest []byte
		opts   crypto.SignerOpts
		key    string
		ok     bool
	}

	server := newFakeServer(t)
	server.Serve(t)
	clientOptions := server.Options(t)

	tt := []testCase{
		{
			name:   "digest-algorithm-mismatch-1",
			key:    "RSA_SIGN_PKCS1_2048_SHA256",
			opts:   crypto.SHA1, // should be sha256
			digest: testkeys.KnownInputHash(crypto.SHA1),
		},
		{
			name:   "digest-length-mismatch-1",
			key:    "RSA_SIGN_PKCS1_2048_SHA256",
			opts:   crypto.SHA256,
			digest: testkeys.KnownInputHash(crypto.SHA1), // should be sha256 hash
		},
		{
			name:   "error-on-sign",
			key:    "RSA_SIGN_PKCS1_2048_SHA256_FORCE_ERROR_ON_ASYMMETRICSIGN",
			opts:   crypto.SHA256,
			digest: testkeys.KnownInputHash(crypto.SHA256),
		},
		{
			name:   "error-req-integrity",
			key:    "RSA_SIGN_PKCS1_2048_SHA256_ERROR_REQ_INTEGRITY",
			opts:   crypto.SHA256,
			digest: testkeys.KnownInputHash(crypto.SHA256),
		},
		{
			name:   "error-resp-integrity",
			key:    "RSA_SIGN_PKCS1_2048_SHA256_ERROR_RESP_INTEGRITY",
			opts:   crypto.SHA256,
			digest: testkeys.KnownInputHash(crypto.SHA256),
		},
		{
			name:   "RSA_SIGN_PKCS1_2048_SHA256",
			key:    "RSA_SIGN_PKCS1_2048_SHA256",
			opts:   crypto.SHA256,
			digest: testkeys.KnownInputHash(crypto.SHA256),
			ok:     true,
		},
		{
			name:   "RSA_SIGN_PKCS1_3072_SHA256",
			key:    "RSA_SIGN_PKCS1_3072_SHA256",
			opts:   crypto.SHA256,
			digest: testkeys.KnownInputHash(crypto.SHA256),
			ok:     true,
		},
		{
			name:   "RSA_SIGN_PKCS1_4096_SHA256",
			key:    "RSA_SIGN_PKCS1_4096_SHA256",
			opts:   crypto.SHA256,
			digest: testkeys.KnownInputHash(crypto.SHA256),
			ok:     true,
		},
		{
			name:   "RSA_SIGN_PKCS1_4096_SHA512",
			key:    "RSA_SIGN_PKCS1_4096_SHA512",
			opts:   crypto.SHA512,
			digest: testkeys.KnownInputHash(crypto.SHA512),
			ok:     true,
		},
		// WithoutOptions
		{
			name:   "RSA_SIGN_PKCS1_2048_SHA256-WithoutOptions",
			key:    "RSA_SIGN_PKCS1_2048_SHA256",
			digest: testkeys.KnownInputHash(crypto.SHA256),
			ok:     true,
		},
		{
			name:   "RSA_SIGN_PKCS1_3072_SHA256-WithoutOptions",
			key:    "RSA_SIGN_PKCS1_3072_SHA256",
			digest: testkeys.KnownInputHash(crypto.SHA256),
			ok:     true,
		},
		{
			name:   "RSA_SIGN_PKCS1_4096_SHA256-WithoutOptions",
			key:    "RSA_SIGN_PKCS1_4096_SHA256",
			digest: testkeys.KnownInputHash(crypto.SHA256),
			ok:     true,
		},
		{
			name:   "RSA_SIGN_PKCS1_4096_SHA512-WithoutOptions",
			key:    "RSA_SIGN_PKCS1_4096_SHA512",
			digest: testkeys.KnownInputHash(crypto.SHA512),
			ok:     true,
		},
		// ECC Keys
		{
			name:   "EC_SIGN_P256_SHA256",
			key:    "EC_SIGN_P256_SHA256",
			opts:   crypto.SHA256,
			digest: testkeys.KnownInputHash(crypto.SHA256),
			ok:     true,
		},
		{
			name:   "EC_SIGN_P384_SHA384",
			key:    "EC_SIGN_P384_SHA384",
			opts:   crypto.SHA384,
			digest: testkeys.KnownInputHash(crypto.SHA384),
			ok:     true,
		},
		// Without Options
		{
			name:   "EC_SIGN_P256_SHA256",
			key:    "EC_SIGN_P256_SHA256",
			digest: testkeys.KnownInputHash(crypto.SHA256),
			ok:     true,
		},
		{
			name:   "EC_SIGN_P384_SHA384",
			key:    "EC_SIGN_P384_SHA384",
			digest: testkeys.KnownInputHash(crypto.SHA384),
			ok:     true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			signer, err := NewSigner(ctx, tc.key, clientOptions...)
			if err != nil {
				t.Fatalf("failed to build signer - %s: %s", tc.key, err)
			}

			signature, err := signer.Sign(
				rand.Reader,
				tc.digest,
				tc.opts,
			)

			if tc.ok {
				if err != nil {
					t.Fatalf("expected no error, got %s", err)
				}
				err = cryptokms.VerifyDigestSignature(
					signer.Public(),
					signer.HashFunc(),
					tc.digest, signature)
				if err != nil {
					t.Errorf("signature verification failed: %s", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
			}
		})
	}
}
