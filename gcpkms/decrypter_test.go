// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package gcpkms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/tprasadtp/cryptokms"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

func Test_Decrypter(t *testing.T) {
	type testCase struct {
		name      string
		key       string
		decrypter *Decrypter
		ok        bool
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
			key:  "DESTROYED_RSA_DECRYPT_OAEP_4096_SHA1",
		},
		{
			name: "unsupported-key-secp256k1",
			key:  "EC_SIGN_SECP256K1_SHA256",
		},
		// HMAC Keys are unsupported for decryption.
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
		// symmetric keys are unsupported for asymmetric decryption.
		{
			name: "unsupported-key-google-symmetric",
			key:  "GOOGLE_SYMMETRIC_ENCRYPTION",
		},
		// PSS Signing Keys are unsupported for asymmetric decryption.
		{
			name: "unsupported-RSA_SIGN_PSS_2048_SHA256",
			key:  "RSA_SIGN_PSS_2048_SHA256",
		},
		{
			name: "unsupported-RSA_SIGN_PSS_3072_SHA256",
			key:  "RSA_SIGN_PSS_3072_SHA256",
		},
		{
			name: "unsupported-RSA_SIGN_PSS_4096_SHA256",
			key:  "RSA_SIGN_PSS_4096_SHA256",
		},
		{
			name: "unsupported-RSA_SIGN_PSS_4096_SHA512",
			key:  "RSA_SIGN_PSS_4096_SHA512",
		},
		// get public key returns corrupted response
		{
			name: "integrity-invalid-RSA_DECRYPT_OAEP_2048_SHA1",
			key:  "ERROR_SRV_INTEGRITY_RSA_DECRYPT_OAEP_2048_SHA1",
		},
		// GetPublicKey returns an error.
		{
			name: "error-on-GetPublicKey",
			key:  "ERROR_ON_GET_PUBLICKEY_RSA_DECRYPT_OAEP_2048_SHA1",
		},
		// Returns RSA Decrypter
		{
			name: "valid-RSA_DECRYPT_OAEP_2048_SHA1",
			key:  "RSA_DECRYPT_OAEP_2048_SHA1",
			ok:   true,
			decrypter: &Decrypter{
				name:  "RSA_DECRYPT_OAEP_2048_SHA1",
				hash:  crypto.SHA1,
				ctime: knownTS,
				algo:  cryptokms.AlgorithmRSA2048,
				pub:   &testkeys.GetRSA2048PrivateKey().PublicKey,
			},
		},
		{
			name: "valid-RSA_DECRYPT_OAEP_3072_SHA1",
			key:  "RSA_DECRYPT_OAEP_3072_SHA1",
			ok:   true,
			decrypter: &Decrypter{
				name:  "RSA_DECRYPT_OAEP_3072_SHA1",
				hash:  crypto.SHA1,
				ctime: knownTS,
				pub:   &testkeys.GetRSA3072PrivateKey().PublicKey,
				algo:  cryptokms.AlgorithmRSA3072,
			},
		},
		{
			name: "valid-RSA_DECRYPT_OAEP_4096_SHA1",
			key:  "RSA_DECRYPT_OAEP_4096_SHA1",
			ok:   true,
			decrypter: &Decrypter{
				name:  "RSA_DECRYPT_OAEP_4096_SHA1",
				hash:  crypto.SHA1,
				ctime: knownTS,
				algo:  cryptokms.AlgorithmRSA4096,
				pub:   &testkeys.GetRSA4096PrivateKey().PublicKey,
			},
		},
		// SHA256
		{
			name: "valid-RSA_DECRYPT_OAEP_2048_SHA256",
			key:  "RSA_DECRYPT_OAEP_2048_SHA256",
			ok:   true,
			decrypter: &Decrypter{
				name:  "RSA_DECRYPT_OAEP_2048_SHA256",
				hash:  crypto.SHA256,
				ctime: knownTS,
				algo:  cryptokms.AlgorithmRSA2048,
				pub:   &testkeys.GetRSA2048PrivateKey().PublicKey,
			},
		},
		{
			name: "valid-RSA_DECRYPT_OAEP_3072_SHA256",
			key:  "RSA_DECRYPT_OAEP_3072_SHA256",
			ok:   true,
			decrypter: &Decrypter{
				name:  "RSA_DECRYPT_OAEP_3072_SHA256",
				hash:  crypto.SHA256,
				ctime: knownTS,
				algo:  cryptokms.AlgorithmRSA3072,
				pub:   &testkeys.GetRSA3072PrivateKey().PublicKey,
			},
		},
		{
			name: "valid-RSA_DECRYPT_OAEP_4096_SHA256",
			key:  "RSA_DECRYPT_OAEP_4096_SHA256",
			ok:   true,
			decrypter: &Decrypter{
				name:  "RSA_DECRYPT_OAEP_4096_SHA256",
				hash:  crypto.SHA256,
				ctime: knownTS,
				algo:  cryptokms.AlgorithmRSA4096,
				pub:   &testkeys.GetRSA4096PrivateKey().PublicKey,
			},
		},
		{
			name: "valid-RSA_DECRYPT_OAEP_4096_SHA512",
			key:  "RSA_DECRYPT_OAEP_4096_SHA512",
			ok:   true,
			decrypter: &Decrypter{
				name:  "RSA_DECRYPT_OAEP_4096_SHA512",
				hash:  crypto.SHA512,
				ctime: knownTS,
				algo:  cryptokms.AlgorithmRSA4096,
				pub:   &testkeys.GetRSA4096PrivateKey().PublicKey,
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			resp, err := NewDecrypter(ctx, tc.key, clientOptions...)
			if tc.ok {
				if err != nil {
					t.Errorf("expected no error, but got %s", err)
				}

				diff := cmp.Diff(
					resp, tc.decrypter,
					cmp.AllowUnexported(Decrypter{}),
					cmpopts.IgnoreFields(Decrypter{}, "client", "mu"))
				if diff != "" {
					t.Errorf("did not get expected response: \n%s", diff)
				}

				if resp.Algorithm() != tc.decrypter.algo {
					t.Errorf("expected algo=%d, got=%d", tc.decrypter.algo, resp.Algorithm())
				}
			} else {
				if err == nil {
					t.Errorf("expected an error, got nil")
				}

				if resp != nil {
					t.Errorf("on error returned decrypter must be nil")
				}
			}
		})
	}
}

func Test_Decrypter_Decrypt_UnInitialized(t *testing.T) {
	decrypter := &Decrypter{}
	_, err := decrypter.Decrypt(
		rand.Reader,
		[]byte("ignored-value"),
		&rsa.OAEPOptions{
			Hash: crypto.SHA256,
		},
	)

	if err == nil {
		t.Errorf("expected error when calling Decrypt on un initialized client")
	}
}

func Test_Decrypter_WithContext(t *testing.T) {
	s := new(Decrypter)
	ctx := context.Background()
	s = s.WithContext(ctx)

	if ctx != s.ctx {
		t.Fatalf("expected %#v to be %#v", ctx, s.ctx)
	}
}

func Test_Decrypter_Decrypt(t *testing.T) {
	type testCase struct {
		name string
		key  string
		ok   bool
		opts crypto.DecrypterOpts
	}

	server := newFakeServer(t)
	server.Serve(t)
	clientOptions := server.Options(t)

	tt := []testCase{
		{
			name: "error-on-sign",
			key:  "FORCE_ERROR_ON_ASYMMETRICDECTYPT_RSA_DECRYPT_OAEP_2048_SHA256",
		},
		{
			name: "error-request-integrity",
			key:  "ERROR_REQ_INTEGRITY_RSA_DECRYPT_OAEP_2048_SHA256",
		},
		{
			name: "error-response-integrity",
			key:  "ERROR_RESP_INTEGRITY_RSA_DECRYPT_OAEP_2048_SHA256",
		},
		{
			name: "error-mismatch-options-hash",
			opts: &rsa.OAEPOptions{
				Hash: crypto.SHA1, // should be SHA256
			},
			key: "RSA_DECRYPT_OAEP_2048_SHA256",
		},
		{
			name: "error-mismatch-options-type",
			opts: rsa.OAEPOptions{ // should be pointer
				Hash: crypto.SHA256,
			},
			key: "RSA_DECRYPT_OAEP_2048_SHA256",
		},
		{
			name: "RSA_DECRYPT_OAEP_2048_SHA256",
			key:  "RSA_DECRYPT_OAEP_2048_SHA256",
			ok:   true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			decrypter, err := NewDecrypter(ctx, tc.key, clientOptions...)
			if err != nil {
				t.Fatalf("failed to build decrypter: %s", err)
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
			plaintext, err := decrypter.Decrypt(
				rand.Reader,
				encrypted,
				tc.opts,
			)

			if tc.ok {
				if err != nil {
					t.Fatalf("expected no error, got %s", err)
				}
				if string(plaintext) != testkeys.KnownInput {
					t.Errorf("expected plaintext=%s, got=%s", testkeys.KnownInput, plaintext)
				}
			} else {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
			}
		})
	}
}
