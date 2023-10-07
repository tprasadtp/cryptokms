// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package awskms

import (
	"context"
	"crypto"
	"crypto/rand"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/tprasadtp/cryptokms"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

func TestNewSigner(t *testing.T) {
	type testCase struct {
		name     string
		region   string
		keyState types.KeyState
		keySpec  types.KeySpec
		keyUsage types.KeyUsageType
		client   Client
		ok       bool
		signer   *Signer
	}
	tt := []testCase{
		{
			name:     "nil-client",
			keyState: types.KeyStateEnabled,
			client:   nil,
			keySpec:  types.KeySpecEccNistP256,
			keyUsage: types.KeyUsageTypeSignVerify,
			region:   "us-east-1",
		},
		// Invalid KeyStateEnabled
		{
			name:     "error-on-describe",
			keyState: types.KeyStateEnabled,
			client:   newMockKMSClient(),
			keySpec:  types.KeySpecEccNistP256,
			keyUsage: types.KeyUsageTypeSignVerify,
			region:   "error-describe",
		},
		{
			name:     "key-still-creating",
			keyState: types.KeyStateCreating,
			client:   newMockKMSClient(),
			keySpec:  types.KeySpecEccNistP256,
			keyUsage: types.KeyUsageTypeSignVerify,
			region:   "us-east-1",
		},
		{
			name:     "key-pending-deletion",
			keyState: types.KeyStatePendingDeletion,
			client:   newMockKMSClient(),
			keySpec:  types.KeySpecEccNistP256,
			keyUsage: types.KeyUsageTypeSignVerify,
			region:   "us-east-1",
		},
		{
			name:     "key-disabled",
			keyState: types.KeyStateDisabled,
			client:   newMockKMSClient(),
			keySpec:  types.KeySpecEccNistP256,
			keyUsage: types.KeyUsageTypeSignVerify,
			region:   "us-east-1",
		},
		// Invalid Key Usage
		{
			name:     "key-usage-encrypt-decrypt",
			keyState: types.KeyStateEnabled,
			client:   newMockKMSClient(),
			keySpec:  types.KeySpecRsa4096,
			keyUsage: types.KeyUsageTypeEncryptDecrypt,
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
			keySpec:  types.KeySpecEccNistP256,
			keyUsage: types.KeyUsageTypeSignVerify,
			region:   "error-get-public-key",
		},
		{
			name:     "unparsable-public-key",
			keyState: types.KeyStateEnabled,
			client:   newMockKMSClient(),
			keySpec:  types.KeySpecRsa4096,
			keyUsage: types.KeyUsageTypeSignVerify,
			region:   "unparsable-public-key",
		},
		{
			name:     "ecc-secg-p256k1",
			keyState: types.KeyStateEnabled,
			client:   newMockKMSClient(),
			keySpec:  types.KeySpecEccSecgP256k1,
			keyUsage: types.KeyUsageTypeSignVerify,
			region:   "us-east-1",
		},
		// Supported EC Signing algorithms
		{
			name:     "ecc-p256",
			keyState: types.KeyStateEnabled,
			client:   newMockKMSClient(),
			keySpec:  types.KeySpecEccNistP256,
			keyUsage: types.KeyUsageTypeSignVerify,
			region:   "us-east-1",
			signer: &Signer{
				keySpec: types.KeySpecEccNistP256,
				//nolint:exhaustive // invalid linter error.
				signingSpecMap: map[crypto.Hash]types.SigningAlgorithmSpec{
					crypto.SHA256: types.SigningAlgorithmSpecEcdsaSha256,
				},
				defaultHasher: crypto.SHA256,
				pub:           testkeys.GetECP256PublicKey(),
				algo:          cryptokms.AlgorithmECP256,
				ctime:         knownTS,
			},
			ok: true,
		},
		{
			name:     "ecc-p384",
			keyState: types.KeyStateEnabled,
			client:   newMockKMSClient(),
			keySpec:  types.KeySpecEccNistP384,
			keyUsage: types.KeyUsageTypeSignVerify,
			region:   "us-east-1",
			signer: &Signer{
				keySpec: types.KeySpecEccNistP384,
				//nolint:exhaustive // invalid linter error.
				signingSpecMap: map[crypto.Hash]types.SigningAlgorithmSpec{
					crypto.SHA384: types.SigningAlgorithmSpecEcdsaSha384,
				},
				defaultHasher: crypto.SHA384,
				pub:           testkeys.GetECP384PublicKey(),
				ctime:         knownTS,
				algo:          cryptokms.AlgorithmECP384,
			},
			ok: true,
		},
		{
			name:     "ecc-p521",
			keyState: types.KeyStateEnabled,
			client:   newMockKMSClient(),
			keySpec:  types.KeySpecEccNistP521,
			keyUsage: types.KeyUsageTypeSignVerify,
			region:   "us-east-1",
			signer: &Signer{
				keySpec: types.KeySpecEccNistP521,
				//nolint:exhaustive // invalid linter error.
				signingSpecMap: map[crypto.Hash]types.SigningAlgorithmSpec{
					crypto.SHA512: types.SigningAlgorithmSpecEcdsaSha512,
				},
				defaultHasher: crypto.SHA512,
				pub:           testkeys.GetECP521PublicKey(),
				ctime:         knownTS,
				algo:          cryptokms.AlgorithmECP521,
			},
			ok: true,
		},
		// Valid RSA Signing keys
		{
			name:     "rsa-2048",
			keyState: types.KeyStateEnabled,
			client:   newMockKMSClient(),
			keySpec:  types.KeySpecRsa2048,
			keyUsage: types.KeyUsageTypeSignVerify,
			region:   "us-east-1",
			signer: &Signer{
				keySpec: types.KeySpecRsa2048,
				//nolint:exhaustive // invalid linter error.
				signingSpecMap: map[crypto.Hash]types.SigningAlgorithmSpec{
					crypto.SHA256: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
					crypto.SHA384: types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
					crypto.SHA512: types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
				},
				defaultHasher: crypto.SHA256,
				pub:           testkeys.GetRSA2048PublicKey(),
				ctime:         knownTS,
				algo:          cryptokms.AlgorithmRSA2048,
			},
			ok: true,
		},
		{
			name:     "rsa-3072",
			keyState: types.KeyStateEnabled,
			client:   newMockKMSClient(),
			keySpec:  types.KeySpecRsa3072,
			keyUsage: types.KeyUsageTypeSignVerify,
			region:   "us-east-1",
			signer: &Signer{
				keySpec: types.KeySpecRsa3072,
				//nolint:exhaustive // invalid linter error.
				signingSpecMap: map[crypto.Hash]types.SigningAlgorithmSpec{
					crypto.SHA256: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
					crypto.SHA384: types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
					crypto.SHA512: types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
				},
				defaultHasher: crypto.SHA256,
				pub:           testkeys.GetRSA3072PublicKey(),
				ctime:         knownTS,
				algo:          cryptokms.AlgorithmRSA3072,
			},
			ok: true,
		},
		{
			name:     "rsa-4096",
			keyState: types.KeyStateEnabled,
			client:   newMockKMSClient(),
			keySpec:  types.KeySpecRsa4096,
			keyUsage: types.KeyUsageTypeSignVerify,
			region:   "us-east-1",
			signer: &Signer{
				keySpec: types.KeySpecRsa4096,
				//nolint:exhaustive // invalid linter error.
				signingSpecMap: map[crypto.Hash]types.SigningAlgorithmSpec{
					crypto.SHA256: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
					crypto.SHA384: types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
					crypto.SHA512: types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
				},
				defaultHasher: crypto.SHA256,
				pub:           testkeys.GetRSA4096PublicKey(),
				ctime:         knownTS,
				algo:          cryptokms.AlgorithmRSA4096,
			},
			ok: true,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			arn := computeKMSKeyArn(tc.keyState, tc.keySpec, tc.keyUsage, tc.region)
			resp, err := NewSigner(ctx, tc.client, arn)

			if tc.ok {
				if err != nil {
					t.Errorf("expected no error, but got %s", err)
				}

				diff := cmp.Diff(
					resp, tc.signer,
					cmp.AllowUnexported(Signer{}),
					cmpopts.IgnoreFields(Signer{}, "client", "keyID", "mu"))
				if diff != "" {
					t.Errorf("did not get expected response: \n%s", diff)
				}

				if resp.Algorithm() != tc.signer.algo {
					t.Errorf("expected algo=%d, got=%d", tc.signer.algo, resp.Algorithm())
				}
			} else {
				if err == nil {
					t.Errorf("expected an error, got nil")
				}

				if resp != nil {
					t.Errorf("on error returned signer must be nil")
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

	if ctx != s.ctx {
		t.Fatalf("expected %#v to be %#v", ctx, s.ctx)
	}
}

func Test_Signer_Sign(t *testing.T) {
	type testCase struct {
		name   string
		key    string
		ok     bool
		digest []byte
		opts   crypto.SignerOpts
	}
	client := newMockKMSClient()
	tt := []testCase{
		// Unsupported hash
		{
			name:   "unsupported-hash",
			digest: testkeys.KnownInputHash(crypto.SHA256),
			opts:   crypto.SHA256, // should be SHA384
			key: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecEccNistP384,
				types.KeyUsageTypeSignVerify),
		},
		{
			name:   "invalid-digest-length",
			digest: testkeys.KnownInputHash(crypto.SHA512), // should be sha256
			opts:   crypto.SHA256,
			key: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecEccNistP256,
				types.KeyUsageTypeSignVerify),
		},
		{
			name:   "errors-on-sign-api-call",
			digest: testkeys.KnownInputHash(crypto.SHA256),
			opts:   crypto.SHA256,
			key: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecEccNistP256,
				types.KeyUsageTypeSignVerify,
				"error-sign",
			),
		},
		{
			name:   "ecc-p256-sha256-default-signer-options",
			digest: testkeys.KnownInputHash(crypto.SHA256),
			key: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecEccNistP256,
				types.KeyUsageTypeSignVerify),
			ok: true,
		},
		{
			name:   "ecc-p256-sha256-with-signer-options",
			digest: testkeys.KnownInputHash(crypto.SHA256),
			opts:   crypto.SHA256,
			key: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecEccNistP256,
				types.KeyUsageTypeSignVerify),
			ok: true,
		},
		{
			name:   "ecc-p384-sha384-default-signer-options",
			digest: testkeys.KnownInputHash(crypto.SHA384),
			key: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecEccNistP384,
				types.KeyUsageTypeSignVerify),
			ok: true,
		},
		{
			name:   "ecc-p384-sha384-with-signer-options",
			digest: testkeys.KnownInputHash(crypto.SHA384),
			opts:   crypto.SHA384,
			key: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecEccNistP384,
				types.KeyUsageTypeSignVerify),
			ok: true,
		},
		// EC P521
		{
			name:   "ecc-p521-sha521-default-signer-options",
			digest: testkeys.KnownInputHash(crypto.SHA512),
			key: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecEccNistP521,
				types.KeyUsageTypeSignVerify),
			ok: true,
		},
		{
			name:   "ecc-p521-sha512-with-signer-options",
			digest: testkeys.KnownInputHash(crypto.SHA512),
			opts:   crypto.SHA512,
			key: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecEccNistP521,
				types.KeyUsageTypeSignVerify),
			ok: true,
		},
		// RSA Keys
		{
			name:   "rsa-2048-default-signer-options",
			digest: testkeys.KnownInputHash(crypto.SHA256),
			key: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa2048,
				types.KeyUsageTypeSignVerify),
			ok: true,
		},
		{
			name:   "rsa-2048-sha256-signer-options",
			digest: testkeys.KnownInputHash(crypto.SHA256),
			opts:   crypto.SHA256,
			key: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa2048,
				types.KeyUsageTypeSignVerify),
			ok: true,
		},
		// {
		// 	name:   "rsa-2048-sha512-signer-options",
		// 	digest: testkeys.KnownInputHash(crypto.SHA512),
		// 	opts:   crypto.SHA512,
		// 	key: computeKMSKeyArn(
		// 		types.KeyStateEnabled,
		// 		types.KeySpecRsa2048,
		// 		types.KeyUsageTypeSignVerify),
		// 	ok: true,
		// },
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			signer, err := NewSigner(ctx, client, tc.key)
			if err != nil {
				t.Fatalf("failed to build signer: %s", err)
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
