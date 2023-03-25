package awskms

import (
	"context"
	"crypto"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/tprasadtp/cryptokms"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

func Test_NewSigner(t *testing.T) {
	type testCase struct {
		Name     string
		Region   string
		KeyState types.KeyState
		KeySpec  types.KeySpec
		KeyUsage types.KeyUsageType
		Client   Client
		Err      error
		Signer   *Signer
	}
	tt := []testCase{
		{
			Name:     "nil-client",
			KeyState: types.KeyStateEnabled,
			Client:   nil,
			KeySpec:  types.KeySpecEccNistP256,
			KeyUsage: types.KeyUsageTypeSignVerify,
			Region:   "us-east-1",
			Err:      cryptokms.ErrInvalidKMSClient,
		},
		// Invalid KeyStateEnabled
		{
			Name:     "error-on-describe",
			KeyState: types.KeyStateEnabled,
			Client:   newMockKMSClient(),
			KeySpec:  types.KeySpecEccNistP256,
			KeyUsage: types.KeyUsageTypeSignVerify,
			Region:   "error-describe",
			Err:      cryptokms.ErrGetKeyMetadata,
		},
		{
			Name:     "key-still-creating",
			KeyState: types.KeyStateCreating,
			Client:   newMockKMSClient(),
			KeySpec:  types.KeySpecEccNistP256,
			KeyUsage: types.KeyUsageTypeSignVerify,
			Region:   "us-east-1",
			Err:      cryptokms.ErrUnusableKeyState,
		},
		{
			Name:     "key-pending-deletion",
			KeyState: types.KeyStatePendingDeletion,
			Client:   newMockKMSClient(),
			KeySpec:  types.KeySpecEccNistP256,
			KeyUsage: types.KeyUsageTypeSignVerify,
			Region:   "us-east-1",
			Err:      cryptokms.ErrUnusableKeyState,
		},
		{
			Name:     "key-disabled",
			KeyState: types.KeyStateDisabled,
			Client:   newMockKMSClient(),
			KeySpec:  types.KeySpecEccNistP256,
			KeyUsage: types.KeyUsageTypeSignVerify,
			Region:   "us-east-1",
			Err:      cryptokms.ErrUnusableKeyState,
		},
		// Invalid Key Usage
		{
			Name:     "key-usage-encrypt-decrypt",
			KeyState: types.KeyStateEnabled,
			Client:   newMockKMSClient(),
			KeySpec:  types.KeySpecRsa4096,
			KeyUsage: types.KeyUsageTypeEncryptDecrypt,
			Region:   "us-east-1",
			Err:      cryptokms.ErrUnsupportedMethod,
		},
		{
			Name:     "key-usage-hmac",
			KeyState: types.KeyStateEnabled,
			Client:   newMockKMSClient(),
			KeySpec:  types.KeySpecHmac256,
			KeyUsage: types.KeyUsageTypeGenerateVerifyMac,
			Region:   "us-east-1",
			Err:      cryptokms.ErrUnsupportedMethod,
		},
		{
			Name:     "key-usage-unknown",
			KeyState: types.KeyStateEnabled,
			Client:   newMockKMSClient(),
			KeySpec:  types.KeySpecRsa4096,
			KeyUsage: types.KeyUsageType("unknown"),
			Region:   "us-east-1",
			Err:      cryptokms.ErrKeyAlgorithm,
		},
		// Error on GetPublicKey API call.
		{
			Name:     "error-on-get-public-key",
			KeyState: types.KeyStateEnabled,
			Client:   newMockKMSClient(),
			KeySpec:  types.KeySpecEccNistP256,
			KeyUsage: types.KeyUsageTypeSignVerify,
			Region:   "error-get-public-key",
			Err:      cryptokms.ErrGetKeyMetadata,
		},
		{
			Name:     "unparsable-public-key",
			KeyState: types.KeyStateEnabled,
			Client:   newMockKMSClient(),
			KeySpec:  types.KeySpecRsa4096,
			KeyUsage: types.KeyUsageTypeSignVerify,
			Region:   "unparsable-public-key",
			Err:      cryptokms.ErrGetKeyMetadata,
		},
		{
			Name:     "ecc-secg-p256k1-has-no-supported-signing-algorithms",
			KeyState: types.KeyStateEnabled,
			Client:   newMockKMSClient(),
			KeySpec:  types.KeySpecEccSecgP256k1,
			KeyUsage: types.KeyUsageTypeSignVerify,
			Region:   "us-east-1",
			Err:      cryptokms.ErrDigestAlgorithm,
		},
		// Supported EC Signing algorithms
		{
			Name:     "ecc-p256",
			KeyState: types.KeyStateEnabled,
			Client:   newMockKMSClient(),
			KeySpec:  types.KeySpecEccNistP256,
			KeyUsage: types.KeyUsageTypeSignVerify,
			Region:   "us-east-1",
			Signer: &Signer{
				keySpec: types.KeySpecEccNistP256,
				//nolint:exhaustive // invalid linter error.
				hashToSigningAlgoMap: map[crypto.Hash]types.SigningAlgorithmSpec{
					crypto.SHA256: types.SigningAlgorithmSpecEcdsaSha256,
				},
				defaultHasher: crypto.SHA256,
				pub:           testkeys.GetECP256PublicKey(),
				ctime:         knownTS,
			},
		},
		{
			Name:     "ecc-p384",
			KeyState: types.KeyStateEnabled,
			Client:   newMockKMSClient(),
			KeySpec:  types.KeySpecEccNistP384,
			KeyUsage: types.KeyUsageTypeSignVerify,
			Region:   "us-east-1",
			Signer: &Signer{
				keySpec: types.KeySpecEccNistP384,
				//nolint:exhaustive // invalid linter error.
				hashToSigningAlgoMap: map[crypto.Hash]types.SigningAlgorithmSpec{
					crypto.SHA384: types.SigningAlgorithmSpecEcdsaSha384,
				},
				defaultHasher: crypto.SHA384,
				pub:           testkeys.GetECP384PublicKey(),
				ctime:         knownTS,
			},
		},
		{
			Name:     "ecc-p521",
			KeyState: types.KeyStateEnabled,
			Client:   newMockKMSClient(),
			KeySpec:  types.KeySpecEccNistP521,
			KeyUsage: types.KeyUsageTypeSignVerify,
			Region:   "us-east-1",
			Signer: &Signer{
				keySpec: types.KeySpecEccNistP521,
				//nolint:exhaustive // invalid linter error.
				hashToSigningAlgoMap: map[crypto.Hash]types.SigningAlgorithmSpec{
					crypto.SHA512: types.SigningAlgorithmSpecEcdsaSha512,
				},
				defaultHasher: crypto.SHA512,
				pub:           testkeys.GetECP521PublicKey(),
				ctime:         knownTS,
			},
		},
		// Valid RSA Signing keys
		{
			Name:     "rsa-2048",
			KeyState: types.KeyStateEnabled,
			Client:   newMockKMSClient(),
			KeySpec:  types.KeySpecRsa2048,
			KeyUsage: types.KeyUsageTypeSignVerify,
			Region:   "us-east-1",
			Signer: &Signer{
				keySpec: types.KeySpecRsa2048,
				//nolint:exhaustive // invalid linter error.
				hashToSigningAlgoMap: map[crypto.Hash]types.SigningAlgorithmSpec{
					crypto.SHA256: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
					crypto.SHA384: types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
					crypto.SHA512: types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
				},
				defaultHasher: crypto.SHA256,
				pub:           testkeys.GetRSA2048PublicKey(),
				ctime:         knownTS,
			},
		},
		{
			Name:     "rsa-3072",
			KeyState: types.KeyStateEnabled,
			Client:   newMockKMSClient(),
			KeySpec:  types.KeySpecRsa3072,
			KeyUsage: types.KeyUsageTypeSignVerify,
			Region:   "us-east-1",
			Signer: &Signer{
				keySpec: types.KeySpecRsa3072,
				//nolint:exhaustive // invalid linter error.
				hashToSigningAlgoMap: map[crypto.Hash]types.SigningAlgorithmSpec{
					crypto.SHA256: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
					crypto.SHA384: types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
					crypto.SHA512: types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
				},
				defaultHasher: crypto.SHA256,
				pub:           testkeys.GetRSA3072PublicKey(),
				ctime:         knownTS,
			},
		},
		{
			Name:     "rsa-4096",
			KeyState: types.KeyStateEnabled,
			Client:   newMockKMSClient(),
			KeySpec:  types.KeySpecRsa4096,
			KeyUsage: types.KeyUsageTypeSignVerify,
			Region:   "us-east-1",
			Signer: &Signer{
				keySpec: types.KeySpecRsa4096,
				//nolint:exhaustive // invalid linter error.
				hashToSigningAlgoMap: map[crypto.Hash]types.SigningAlgorithmSpec{
					crypto.SHA256: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
					crypto.SHA384: types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
					crypto.SHA512: types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
				},
				defaultHasher: crypto.SHA256,
				pub:           testkeys.GetRSA4096PublicKey(),
				ctime:         knownTS,
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()
			arn := computeKMSKeyArn(tc.KeyState, tc.KeySpec, tc.KeyUsage, tc.Region)
			resp, err := NewSigner(ctx, tc.Client, arn)
			if !errors.Is(err, tc.Err) {
				t.Errorf("expected error=%+v, but got=%+v", tc.Err, err)
			}
			diff := cmp.Diff(
				resp, tc.Signer,
				cmp.AllowUnexported(Signer{}),
				cmpopts.IgnoreFields(Signer{}, "client", "keyID"))
			if diff != "" {
				t.Errorf("did not get expected response: \n%s", diff)
			}
		})
	}
}

func Test_Signer_UnInitialized(t *testing.T) {
	signer := &Signer{}
	_, err := signer.Sign(
		rand.Reader,
		testkeys.KnownInputHash(crypto.SHA256),
		crypto.SHA256,
	)

	if !errors.Is(err, cryptokms.ErrInvalidKMSClient) {
		t.Errorf("expected error=%+v, but got=%+v", cryptokms.ErrInvalidKMSClient, err)
	}
}

func Test_Signer_Sign(t *testing.T) {
	type testCase struct {
		Name          string
		KeyID         string
		Err           error
		Digest        []byte
		SignerOptions crypto.SignerOpts
	}
	client := newMockKMSClient()
	tt := []testCase{
		// Unsupported hash
		{
			Name:          "unsupported-hash",
			Err:           cryptokms.ErrDigestAlgorithm,
			Digest:        testkeys.KnownInputHash(crypto.SHA256),
			SignerOptions: crypto.SHA256, // should be SHA384
			KeyID: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecEccNistP384,
				types.KeyUsageTypeSignVerify),
		},
		{
			Name:          "invalid-digest-length",
			Err:           cryptokms.ErrDigestLength,
			Digest:        testkeys.KnownInputHash(crypto.SHA512), // should be sha256
			SignerOptions: crypto.SHA256,
			KeyID: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecEccNistP256,
				types.KeyUsageTypeSignVerify),
		},
		{
			Name:          "errors-on-sign-api-call",
			Err:           cryptokms.ErrAsymmetricSign,
			Digest:        testkeys.KnownInputHash(crypto.SHA256),
			SignerOptions: crypto.SHA256,
			KeyID: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecEccNistP256,
				types.KeyUsageTypeSignVerify,
				"error-sign",
			),
		},
		{
			Name:   "ecc-p256-sha256-default-signer-options",
			Digest: testkeys.KnownInputHash(crypto.SHA256),
			KeyID: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecEccNistP256,
				types.KeyUsageTypeSignVerify),
		},
		{
			Name:          "ecc-p256-sha256-with-signer-options",
			Digest:        testkeys.KnownInputHash(crypto.SHA256),
			SignerOptions: crypto.SHA256,
			KeyID: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecEccNistP256,
				types.KeyUsageTypeSignVerify),
		},
		{
			Name:   "ecc-p384-sha384-default-signer-options",
			Digest: testkeys.KnownInputHash(crypto.SHA384),
			KeyID: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecEccNistP384,
				types.KeyUsageTypeSignVerify),
		},
		{
			Name:          "ecc-p384-sha384-with-signer-options",
			Digest:        testkeys.KnownInputHash(crypto.SHA384),
			SignerOptions: crypto.SHA384,
			KeyID: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecEccNistP384,
				types.KeyUsageTypeSignVerify),
		},
		// EC P521
		{
			Name:   "ecc-p521-sha521-default-signer-options",
			Digest: testkeys.KnownInputHash(crypto.SHA512),
			KeyID: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecEccNistP521,
				types.KeyUsageTypeSignVerify),
		},
		{
			Name:          "ecc-p521-sha512-with-signer-options",
			Digest:        testkeys.KnownInputHash(crypto.SHA512),
			SignerOptions: crypto.SHA512,
			KeyID: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecEccNistP521,
				types.KeyUsageTypeSignVerify),
		},
		// RSA Keys
		{
			Name:   "rsa-2048-default-signer-options",
			Digest: testkeys.KnownInputHash(crypto.SHA256),
			KeyID: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa2048,
				types.KeyUsageTypeSignVerify),
		},
		{
			Name:          "rsa-2048-sha256-signer-options",
			Digest:        testkeys.KnownInputHash(crypto.SHA256),
			SignerOptions: crypto.SHA256,
			KeyID: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa2048,
				types.KeyUsageTypeSignVerify),
		},
		{
			Name:          "rsa-2048-sha2512-signer-options",
			Digest:        testkeys.KnownInputHash(crypto.SHA512),
			SignerOptions: crypto.SHA512,
			KeyID: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa2048,
				types.KeyUsageTypeSignVerify),
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()
			signer, err := NewSigner(ctx, client, tc.KeyID)
			if err != nil {
				t.Fatalf("failed to build signer: %s", err)
			}

			signature, err := signer.Sign(
				rand.Reader,
				tc.Digest,
				tc.SignerOptions,
			)

			if !errors.Is(err, tc.Err) {
				t.Fatalf("expected err=%s, got err=%s", tc.Err, err)
			}

			// only verify signatures if signing did not return an error.
			if err == nil {
				hasher := signer.HashFunc()
				if tc.SignerOptions != nil {
					hasher = tc.SignerOptions.HashFunc()
				}

				err = cryptokms.VerifyDigestSignature(signer.Public(), hasher, tc.Digest, signature)
				if err != nil {
					t.Errorf("failed to verify signature: %s", err)
				}

				// ensure created at is not zero time
				if signer.CreatedAt().IsZero() {
					t.Errorf("CreatedAt() must not be zero")
				}
			}
		})
	}
}
