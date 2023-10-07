// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package awskms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/tprasadtp/cryptokms"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

func TestNewDecrypter(t *testing.T) {
	type testCase struct {
		name      string
		region    string
		keyState  types.KeyState
		keySpec   types.KeySpec
		keyUsage  types.KeyUsageType
		client    Client
		ok        bool
		decrypter *Decrypter
	}
	tt := []testCase{
		{
			name:     "nil-client",
			keyState: types.KeyStateEnabled,
			client:   nil,
			keySpec:  types.KeySpecRsa4096,
			keyUsage: types.KeyUsageTypeEncryptDecrypt,
			region:   "us-east-1",
		},
		// Invalid KeyStateEnabled
		{
			name:     "error-on-describe",
			keyState: types.KeyStateEnabled,
			client:   newMockKMSClient(),
			keySpec:  types.KeySpecRsa4096,
			keyUsage: types.KeyUsageTypeEncryptDecrypt,
			region:   "error-describe",
		},
		{
			name:     "key-still-creating",
			keyState: types.KeyStateCreating,
			client:   newMockKMSClient(),
			keySpec:  types.KeySpecRsa4096,
			keyUsage: types.KeyUsageTypeEncryptDecrypt,
			region:   "us-east-1",
		},
		{
			name:     "key-pending-deletion",
			keyState: types.KeyStatePendingDeletion,
			client:   newMockKMSClient(),
			keySpec:  types.KeySpecRsa4096,
			keyUsage: types.KeyUsageTypeEncryptDecrypt,
			region:   "us-east-1",
		},
		{
			name:     "key-disabled",
			keyState: types.KeyStateDisabled,
			client:   newMockKMSClient(),
			keySpec:  types.KeySpecRsa4096,
			keyUsage: types.KeyUsageTypeEncryptDecrypt,
			region:   "us-east-1",
		},
		// Invalid Key Usage
		{
			name:     "key-usage-sign-verify",
			keyState: types.KeyStateEnabled,
			client:   newMockKMSClient(),
			keySpec:  types.KeySpecRsa4096,
			keyUsage: types.KeyUsageTypeSignVerify,
			region:   "us-east-1",
		},
		{
			name:     "key-usage-hmac",
			keyState: types.KeyStateEnabled,
			client:   newMockKMSClient(),
			keySpec:  types.KeySpecHmac256,
			keyUsage: types.KeyUsageTypeGenerateVerifyMac,
			region:   "us-east-1",
		},
		{
			name:     "key-usage-unknown",
			keyState: types.KeyStateEnabled,
			client:   newMockKMSClient(),
			keySpec:  types.KeySpecRsa4096,
			keyUsage: types.KeyUsageType("unknown"),
			region:   "us-east-1",
		},
		// Error on GetPublicKey API call.
		{
			name:     "error-on-get-public-key",
			keyState: types.KeyStateEnabled,
			client:   newMockKMSClient(),
			keySpec:  types.KeySpecRsa4096,
			keyUsage: types.KeyUsageTypeEncryptDecrypt,
			region:   "error-get-public-key",
		},
		{
			name:     "unparsable-public-key",
			keyState: types.KeyStateEnabled,
			client:   newMockKMSClient(),
			keySpec:  types.KeySpecRsa4096,
			keyUsage: types.KeyUsageTypeEncryptDecrypt,
			region:   "unparsable-public-key",
		},
		// Valid RSA keys
		{
			name:     "rsa-2048",
			keyState: types.KeyStateEnabled,
			client:   newMockKMSClient(),
			keySpec:  types.KeySpecRsa2048,
			keyUsage: types.KeyUsageTypeEncryptDecrypt,
			region:   "us-east-1",
			decrypter: &Decrypter{
				keySpec: types.KeySpecRsa2048,
				//nolint:exhaustive // invalid linter error.
				hashToEncryptionAlgoMap: map[crypto.Hash]types.EncryptionAlgorithmSpec{
					crypto.SHA1:   types.EncryptionAlgorithmSpecRsaesOaepSha1,
					crypto.SHA256: types.EncryptionAlgorithmSpecRsaesOaepSha256,
				},
				defaultHasher:    crypto.SHA256,
				pub:              testkeys.GetRSA2048PublicKey(),
				maxCiphertextLen: 2048 / 8,
				ctime:            knownTS,
				algo:             cryptokms.AlgorithmRSA2048,
			},
			ok: true,
		},
		{
			name:     "rsa-3072",
			keyState: types.KeyStateEnabled,
			client:   newMockKMSClient(),
			keySpec:  types.KeySpecRsa3072,
			keyUsage: types.KeyUsageTypeEncryptDecrypt,
			region:   "us-east-1",
			decrypter: &Decrypter{
				keySpec: types.KeySpecRsa3072,
				//nolint:exhaustive // invalid linter error.
				hashToEncryptionAlgoMap: map[crypto.Hash]types.EncryptionAlgorithmSpec{
					crypto.SHA1:   types.EncryptionAlgorithmSpecRsaesOaepSha1,
					crypto.SHA256: types.EncryptionAlgorithmSpecRsaesOaepSha256,
				},
				defaultHasher:    crypto.SHA256,
				pub:              testkeys.GetRSA3072PublicKey(),
				maxCiphertextLen: 3072 / 8,
				ctime:            knownTS,
				algo:             cryptokms.AlgorithmRSA3072,
			},
			ok: true,
		},
		{
			name:     "rsa-4096",
			keyState: types.KeyStateEnabled,
			client:   newMockKMSClient(),
			keySpec:  types.KeySpecRsa4096,
			keyUsage: types.KeyUsageTypeEncryptDecrypt,
			region:   "us-east-1",
			decrypter: &Decrypter{
				keySpec: types.KeySpecRsa4096,
				//nolint:exhaustive // invalid linter error.
				hashToEncryptionAlgoMap: map[crypto.Hash]types.EncryptionAlgorithmSpec{
					crypto.SHA1:   types.EncryptionAlgorithmSpecRsaesOaepSha1,
					crypto.SHA256: types.EncryptionAlgorithmSpecRsaesOaepSha256,
				},
				defaultHasher:    crypto.SHA256,
				pub:              testkeys.GetRSA4096PublicKey(),
				maxCiphertextLen: 4096 / 8,
				ctime:            knownTS,
				algo:             cryptokms.AlgorithmRSA4096,
			},
			ok: true,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			arn := computeKMSKeyArn(tc.keyState, tc.keySpec, tc.keyUsage, tc.region)
			resp, err := NewDecrypter(ctx, tc.client, arn)
			if tc.ok {
				if err != nil {
					t.Errorf("expected no error, but got %s", err)
				}

				diff := cmp.Diff(
					resp, tc.decrypter,
					cmp.AllowUnexported(Decrypter{}),
					cmpopts.IgnoreFields(Decrypter{}, "client", "keyID", "mu"))
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

func TestDecrypter_WithContext(t *testing.T) {
	s := new(Decrypter)
	ctx := context.Background()
	s = s.WithContext(ctx)

	if ctx != s.ctx {
		t.Fatalf("expected %#v to be %#v", ctx, s.ctx)
	}
}

func TestDecrypter_Decrypt(t *testing.T) {
	type testCase struct {
		name       string
		key        string
		ok         bool
		ciphertext []byte
		opts       crypto.DecrypterOpts
	}

	client := newMockKMSClient()
	tt := []testCase{
		{
			name: "rsa-4096-oaep-hash-not-equal-to-mgf-hash",
			ciphertext: func() []byte {
				encrypted, _ := rsa.EncryptOAEP(
					crypto.SHA256.New(), rand.Reader,
					testkeys.GetRSA4096PublicKey(),
					[]byte(testkeys.KnownInput), nil,
				)
				return encrypted
			}(),
			key: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa4096,
				types.KeyUsageTypeEncryptDecrypt),
			opts: &rsa.OAEPOptions{
				Hash:    crypto.SHA256,
				MGFHash: crypto.SHA1, // should be sha256 or zero value
			},
		},
		{
			name: "rsa-4096-oaep-ciphertext-too-large",
			ciphertext: func() []byte {
				buf := make([]byte, 4096/8+1)
				//nolint:errcheck // ignore as test will fail if err != nil
				rand.Reader.Read(buf)
				return buf
			}(),
			key: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa4096,
				types.KeyUsageTypeEncryptDecrypt),
			opts: &rsa.OAEPOptions{
				Hash: crypto.SHA256,
			},
		},
		{
			name: "rsa-4096-default-options",
			ciphertext: func() []byte {
				encrypted, _ := rsa.EncryptOAEP(
					crypto.SHA256.New(), rand.Reader,
					testkeys.GetRSA4096PublicKey(),
					[]byte(testkeys.KnownInput), nil,
				)
				return encrypted
			}(),
			key: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa4096,
				types.KeyUsageTypeEncryptDecrypt),
			ok: true,
		},
		{
			name: "rsa-4096-valid-options",
			ciphertext: func() []byte {
				encrypted, _ := rsa.EncryptOAEP(
					crypto.SHA256.New(), rand.Reader,
					testkeys.GetRSA4096PublicKey(),
					[]byte(testkeys.KnownInput), nil,
				)
				return encrypted
			}(),
			opts: &rsa.OAEPOptions{
				Hash: crypto.SHA256,
			},
			key: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa4096,
				types.KeyUsageTypeEncryptDecrypt),
			ok: true,
		},
		{
			name: "rsa-4096-sha1",
			ciphertext: func() []byte {
				encrypted, _ := rsa.EncryptOAEP(
					crypto.SHA1.New(), rand.Reader,
					testkeys.GetRSA4096PublicKey(),
					[]byte(testkeys.KnownInput), nil,
				)
				return encrypted
			}(),
			opts: &rsa.OAEPOptions{
				Hash: crypto.SHA1,
			},
			key: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa4096,
				types.KeyUsageTypeEncryptDecrypt),
			ok: true,
		},
		{
			name: "rsa-4096-sha512-unsupported",
			ciphertext: func() []byte {
				encrypted, _ := rsa.EncryptOAEP(
					crypto.SHA512.New(), rand.Reader,
					testkeys.GetRSA4096PublicKey(),
					[]byte(testkeys.KnownInput), nil,
				)
				return encrypted
			}(),
			opts: &rsa.OAEPOptions{
				Hash: crypto.SHA512,
			},
			key: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa4096,
				types.KeyUsageTypeEncryptDecrypt),
		},
		{
			name: "rsa-4096-PKCS1v15DecryptOptions-unsupported",
			ciphertext: func() []byte {
				encrypted, _ := rsa.EncryptOAEP(
					crypto.SHA256.New(), rand.Reader,
					testkeys.GetRSA4096PublicKey(),
					[]byte(testkeys.KnownInput), nil,
				)
				return encrypted
			}(),
			opts: &rsa.PKCS1v15DecryptOptions{},
			key: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa4096,
				types.KeyUsageTypeEncryptDecrypt),
		},
		{
			name: "rsa-4096-unsupported-type",
			ciphertext: func() []byte {
				encrypted, _ := rsa.EncryptOAEP(
					crypto.SHA256.New(), rand.Reader,
					testkeys.GetRSA4096PublicKey(),
					[]byte(testkeys.KnownInput), nil,
				)
				return encrypted
			}(),
			opts: rsa.OAEPOptions{Hash: crypto.SHA256}, // should be pointer
			key: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa4096,
				types.KeyUsageTypeEncryptDecrypt),
		},
		{
			name: "rsa-4096-error-on-decrypt-api-call",
			ciphertext: func() []byte {
				encrypted, _ := rsa.EncryptOAEP(
					crypto.SHA256.New(), rand.Reader,
					testkeys.GetRSA4096PublicKey(),
					[]byte(testkeys.KnownInput), nil,
				)
				return encrypted
			}(),
			key: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa4096,
				types.KeyUsageTypeEncryptDecrypt,
				"error-decrypt"),
		},
		{
			name: "rsa-3072-sha256",
			ciphertext: func() []byte {
				encrypted, _ := rsa.EncryptOAEP(
					crypto.SHA256.New(), rand.Reader,
					testkeys.GetRSA3072PublicKey(),
					[]byte(testkeys.KnownInput), nil,
				)
				return encrypted
			}(),
			key: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa3072,
				types.KeyUsageTypeEncryptDecrypt),
			ok: true,
		},
		{
			name: "rsa-2048-sha256",
			ciphertext: func() []byte {
				encrypted, _ := rsa.EncryptOAEP(
					crypto.SHA256.New(), rand.Reader,
					testkeys.GetRSA2048PublicKey(),
					[]byte(testkeys.KnownInput), nil,
				)
				return encrypted
			}(),
			key: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa2048,
				types.KeyUsageTypeEncryptDecrypt),
			ok: true,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			decrypter, err := NewDecrypter(ctx, client, tc.key)
			if err != nil {
				t.Fatalf("failed to build decrypter(%s): %s", tc.key, err)
			}

			if err != nil {
				t.Fatalf("failed to encrypt: %s", err)
			}
			plaintext, err := decrypter.Decrypt(
				rand.Reader,
				tc.ciphertext,
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
