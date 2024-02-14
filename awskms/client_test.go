// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package awskms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/google/uuid"
	"github.com/tprasadtp/cryptokms/internal/shared"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

var _ Client = (*mockKMSClient)(nil)

// Forced errors.
var (
	errForced = fmt.Errorf("awskms(mock): forced error for unit testing")
)

// well known timestamp.
var knownTS = time.Unix(1136239445, 0)

type KeyInfo struct {
	KeyArn               string
	KeyState             types.KeyState
	Enabled              bool
	Signer               crypto.Signer
	Decrypter            crypto.Decrypter
	PublicKeyPEM         []byte
	KeySpec              types.KeySpec
	KeyUsage             types.KeyUsageType
	SigningAlgorithms    []types.SigningAlgorithmSpec
	EncryptionAlgorithms []types.EncryptionAlgorithmSpec
	CreatedAt            time.Time
}

// mock KMS client implements Client interface to mock in tests.
type mockKMSClient struct {
	store map[string]KeyInfo
}

// Deterministic key ARN based on key state and key specs and key usage.
// region is used to force errors on some operations.
func computeKMSKeyArn(keyState types.KeyState, keySpec types.KeySpec, keyUsage types.KeyUsageType, region ...string) string {
	buf := &bytes.Buffer{}
	if len(region) == 0 {
		region = make([]string, 1)
		region[0] = "us-east-1"
	}

	buf.WriteString(string(keyState))
	buf.WriteString("_")
	buf.WriteString(string(keySpec))
	buf.WriteString("_")
	buf.WriteString(string(keyUsage))
	return fmt.Sprintf("arn:aws:kms:%s:000000000000:key/%s", region[0], uuid.NewSHA1(uuid.NameSpaceDNS, buf.Bytes()).String())
}

// A wrapper around MarshalPKIXPublicKey.
func mustMarshalPKIXPublicKey(pub crypto.PublicKey) []byte {
	rv, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal public key: %s", err))
	}
	return rv
}

// create a new KMS client for mocking.
func newMockKMSClient() *mockKMSClient {
	rv := mockKMSClient{
		store: make(map[string]KeyInfo),
	}

	// map KeySpec -> List[SigningAlgorithmSpec]
	// includes unsupported.
	//nolint: exhaustive // not necessary as those sign/decrypt paths are not reached.
	keySpecToSigningAlgorithms := map[types.KeySpec][]types.SigningAlgorithmSpec{
		types.KeySpecRsa4096: {
			types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
			types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
			types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
			types.SigningAlgorithmSpecRsassaPssSha256,
			types.SigningAlgorithmSpecRsassaPssSha384,
			types.SigningAlgorithmSpecRsassaPssSha512,
		},
		types.KeySpecRsa3072: {
			types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
			types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
			types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
			types.SigningAlgorithmSpecRsassaPssSha256,
			types.SigningAlgorithmSpecRsassaPssSha384,
			types.SigningAlgorithmSpecRsassaPssSha512,
		},
		types.KeySpecRsa2048: {
			types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
			types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
			types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
			types.SigningAlgorithmSpecRsassaPssSha256,
			types.SigningAlgorithmSpecRsassaPssSha384,
			types.SigningAlgorithmSpecRsassaPssSha512,
		},
		types.KeySpecEccNistP256: {types.SigningAlgorithmSpecEcdsaSha256},
		types.KeySpecEccNistP384: {types.SigningAlgorithmSpecEcdsaSha384},
		types.KeySpecEccNistP521: {types.SigningAlgorithmSpecEcdsaSha512},
	}

	// map KeySpec -> List[EncryptionAlgorithmSpec]
	//nolint: exhaustive // not necessary as those sign/decrypt paths are not reached.
	keySpecToEncryptionAlgorithms := map[types.KeySpec][]types.EncryptionAlgorithmSpec{
		types.KeySpecRsa4096: {
			types.EncryptionAlgorithmSpecRsaesOaepSha1,
			types.EncryptionAlgorithmSpecRsaesOaepSha256,
		},
		types.KeySpecRsa3072: {
			types.EncryptionAlgorithmSpecRsaesOaepSha1,
			types.EncryptionAlgorithmSpecRsaesOaepSha256,
		},
		types.KeySpecRsa2048: {
			types.EncryptionAlgorithmSpecRsaesOaepSha1,
			types.EncryptionAlgorithmSpecRsaesOaepSha256,
		},
	}

	// Map KeySpec|KeyUsageTypeSignVerify -> test private keys.
	//nolint: exhaustive // not necessary as those sign/decrypt paths are not reached.
	keySpecToSigner := map[types.KeySpec]crypto.Signer{
		types.KeySpecRsa4096:     testkeys.GetRSA4096PrivateKey(),
		types.KeySpecRsa3072:     testkeys.GetRSA3072PrivateKey(),
		types.KeySpecRsa2048:     testkeys.GetRSA2048PrivateKey(),
		types.KeySpecEccNistP521: testkeys.GetECP521PrivateKey(),
		types.KeySpecEccNistP384: testkeys.GetECP384PrivateKey(),
		types.KeySpecEccNistP256: testkeys.GetECP256PrivateKey(),
		// ignore mismatch as we want to trigger unsupported key code path.
		// delete this if P256k1 support is available in stdlib.
		types.KeySpecEccSecgP256k1: testkeys.GetECP256PrivateKey(),
	}

	// Map KeySpec|KeyUsageTypeEncryptDecrypt -> test private keys.
	//nolint: exhaustive // not necessary as those sign/decrypt paths are not reached.
	keySpecToDecrypter := map[types.KeySpec]crypto.Decrypter{
		types.KeySpecRsa4096: testkeys.GetRSA4096PrivateKey(),
		types.KeySpecRsa3072: testkeys.GetRSA3072PrivateKey(),
		types.KeySpecRsa2048: testkeys.GetRSA2048PrivateKey(),
	}

	// Map KeySpec -> test public key PEM.
	//nolint: exhaustive // not necessary as those sign/decrypt paths are not reached.
	keySpecToPublicKeyPEM := map[types.KeySpec][]byte{
		types.KeySpecRsa4096:     mustMarshalPKIXPublicKey(testkeys.GetRSA4096PublicKey()),
		types.KeySpecRsa3072:     mustMarshalPKIXPublicKey(testkeys.GetRSA3072PublicKey()),
		types.KeySpecRsa2048:     mustMarshalPKIXPublicKey(testkeys.GetRSA2048PublicKey()),
		types.KeySpecEccNistP521: mustMarshalPKIXPublicKey(testkeys.GetECP521PublicKey()),
		types.KeySpecEccNistP384: mustMarshalPKIXPublicKey(testkeys.GetECP384PublicKey()),
		types.KeySpecEccNistP256: mustMarshalPKIXPublicKey(testkeys.GetECP256PublicKey()),
		// ignore mismatch as we want to trigger unsupported key code path.
		types.KeySpecEccSecgP256k1: mustMarshalPKIXPublicKey(testkeys.GetECP256PublicKey()),
	}

	signingKeySpecs := []types.KeySpec{
		types.KeySpecEccNistP256,
		types.KeySpecEccNistP384,
		types.KeySpecEccNistP521,
		types.KeySpecRsa2048,
		types.KeySpecRsa3072,
		types.KeySpecRsa4096,
		types.KeySpecEccSecgP256k1,
	}

	encryptionKeySpecs := []types.KeySpec{
		types.KeySpecRsa2048,
		types.KeySpecRsa3072,
		types.KeySpecRsa4096,
	}

	hmacKespecs := []types.KeySpec{
		types.KeySpecHmac224,
		types.KeySpecHmac256,
		types.KeySpecHmac384,
		types.KeySpecHmac512,
	}

	// Yes, most if not all generated keys are never used in tests,
	// but this greatly simplifies tests as its just a bunch of loops.
	//
	// Iterate over "regions". region's value is in arn and can be used to force errors.
	for _, region := range []string{"us-east-1", "error-describe", "error-get-public-key", "error-sign", "error-decrypt"} {
		// Iterate over key states.
		for _, keyState := range types.KeyState("").Values() {
			// Signing Keys
			// -----------------------------------------------------------------
			// iterate over signing keys
			for _, keySpec := range signingKeySpecs {
				keyUsage := types.KeyUsageTypeSignVerify
				arn := computeKMSKeyArn(keyState, keySpec, keyUsage, region)
				// t.Logf("KeySpec=%s KeyState=%s KeyUsage=%s KeyArn=%s Region=%s",
				// 	keySpec, keyState, keyUsage, arn, region)
				keyInfo := KeyInfo{
					KeyArn:    arn,
					Enabled:   keyState == types.KeyStateEnabled,
					KeyState:  keyState,
					KeyUsage:  keyUsage,
					KeySpec:   keySpec,
					CreatedAt: knownTS,
				}

				if signingAlgos, ok := keySpecToSigningAlgorithms[keySpec]; ok {
					keyInfo.SigningAlgorithms = signingAlgos
				}

				if signer, ok := keySpecToSigner[keySpec]; ok {
					keyInfo.Signer = signer
				}

				if pubPEM, ok := keySpecToPublicKeyPEM[keySpec]; ok {
					keyInfo.PublicKeyPEM = pubPEM
				}
				rv.store[arn] = keyInfo
			}

			// iterate over encryption keys
			// -----------------------------------------------------------------
			for _, keySpec := range encryptionKeySpecs {
				keyUsage := types.KeyUsageTypeEncryptDecrypt
				arn := computeKMSKeyArn(keyState, keySpec, keyUsage, region)
				// t.Logf("KeySpec=%s KeyState=%s KeyUsage=%s KeyArn=%s Region=%s",
				// 	keySpec, keyState, keyUsage, arn, region)
				keyInfo := KeyInfo{
					KeyArn:    arn,
					Enabled:   keyState == types.KeyStateEnabled,
					KeyState:  keyState,
					KeyUsage:  keyUsage,
					KeySpec:   keySpec,
					CreatedAt: knownTS,
				}

				if encryptionAlgos, ok := keySpecToEncryptionAlgorithms[keySpec]; ok {
					keyInfo.EncryptionAlgorithms = encryptionAlgos
				}

				if decrypter, ok := keySpecToDecrypter[keySpec]; ok {
					keyInfo.Decrypter = decrypter
				}

				if pubPEM, ok := keySpecToPublicKeyPEM[keySpec]; ok {
					keyInfo.PublicKeyPEM = pubPEM
				}
				rv.store[arn] = keyInfo
			}

			// iterate over hmac keys (not used except for metadata checks)
			// -----------------------------------------------------------------
			for _, keySpec := range hmacKespecs {
				keyUsage := types.KeyUsageTypeGenerateVerifyMac
				arn := computeKMSKeyArn(keyState, keySpec, keyUsage, region)
				// t.Logf("KeySpec=%s KeyState=%s KeyUsage=%s KeyArn=%s Region=%s",
				// 	keySpec, keyState, keyUsage, arn, region)
				keyInfo := KeyInfo{
					KeyArn:    arn,
					Enabled:   keyState == types.KeyStateEnabled,
					KeyState:  keyState,
					KeyUsage:  keyUsage,
					KeySpec:   keySpec,
					CreatedAt: knownTS,
				}
				rv.store[arn] = keyInfo
			}
		}
	}

	// following entires are there to ensure that unknown
	// un-parsable data does not trigger panics.
	// it is unlikely to ever occur.
	arn1 := computeKMSKeyArn(types.KeyStateEnabled, types.KeySpecRsa4096, types.KeyUsageType("unknown"))
	rv.store[arn1] = KeyInfo{
		KeyArn:            arn1,
		KeyState:          types.KeyStateEnabled,
		KeyUsage:          types.KeyUsageType("unknown"),
		KeySpec:           types.KeySpecRsa4096,
		PublicKeyPEM:      shared.MustMarshalPublicKey(testkeys.GetRSA4096PublicKey()),
		Signer:            testkeys.GetRSA4096PrivateKey(),
		SigningAlgorithms: keySpecToSigningAlgorithms[types.KeySpecRsa4096],
		CreatedAt:         knownTS,
	}

	for _, v := range []types.KeyUsageType{types.KeyUsageTypeEncryptDecrypt, types.KeyUsageTypeSignVerify} {
		// Unparsable signing key and encryption keys
		unparsableKeyArn := computeKMSKeyArn(
			types.KeyStateEnabled,
			types.KeySpecRsa4096,
			v,
			"unparsable-public-key",
		)
		rv.store[unparsableKeyArn] = KeyInfo{
			KeyArn:       unparsableKeyArn,
			KeyState:     types.KeyStateEnabled,
			KeySpec:      types.KeySpecRsa4096,
			KeyUsage:     v,
			CreatedAt:    knownTS,
			PublicKeyPEM: []byte("foo bar"), // invalid
			// Both Signer and decrypter are populated as
			// this is used in unit test for both signer and decrypter.
			Signer:               testkeys.GetRSA4096PrivateKey(),
			Decrypter:            testkeys.GetRSA4096PrivateKey(),
			SigningAlgorithms:    keySpecToSigningAlgorithms[types.KeySpecRsa4096],
			EncryptionAlgorithms: keySpecToEncryptionAlgorithms[types.KeySpecRsa4096],
		}
	}

	return &rv
}

// Describe Key describes key and its metadata.
func (m *mockKMSClient) DescribeKey(_ context.Context, params *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if strings.Contains(*params.KeyId, "error-describe") {
		return nil, fmt.Errorf("%w: action=describe", errForced)
	}
	metadata := m.store[*params.KeyId]
	return &kms.DescribeKeyOutput{
		KeyMetadata: &types.KeyMetadata{
			AWSAccountId:                aws.String("000000000000"),
			Arn:                         &metadata.KeyArn,
			Enabled:                     metadata.Enabled,
			KeyState:                    metadata.KeyState,
			KeySpec:                     metadata.KeySpec,
			KeyUsage:                    metadata.KeyUsage,
			CreationDate:                &metadata.CreatedAt,
			Origin:                      types.OriginTypeAwsKms,
			EncryptionAlgorithms:        metadata.EncryptionAlgorithms,
			SigningAlgorithms:           metadata.SigningAlgorithms,
			KeyManager:                  types.KeyManagerTypeCustomer,
			MultiRegion:                 aws.Bool(false),
			PendingDeletionWindowInDays: aws.Int32(7),
			Description:                 aws.String("Unit Test"),
		},
	}, nil
}

// get public key.
func (m *mockKMSClient) GetPublicKey(_ context.Context, params *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	if strings.Contains(*params.KeyId, "error-get-public-key") {
		return nil, fmt.Errorf("%w: action=get-public-key", errForced)
	}
	metadata := m.store[*params.KeyId]
	return &kms.GetPublicKeyOutput{
		KeyId:                &metadata.KeyArn,
		KeySpec:              metadata.KeySpec,
		KeyUsage:             metadata.KeyUsage,
		EncryptionAlgorithms: metadata.EncryptionAlgorithms,
		SigningAlgorithms:    metadata.SigningAlgorithms,
		PublicKey:            metadata.PublicKeyPEM,
	}, nil
}

func (m *mockKMSClient) Sign(_ context.Context, params *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	if strings.Contains(*params.KeyId, "error-sign") {
		return nil, fmt.Errorf("%w: action=sign", errForced)
	}
	metadata := m.store[*params.KeyId]

	var signature []byte
	var err error

	switch params.SigningAlgorithm {
	case types.SigningAlgorithmSpecEcdsaSha256:
		if metadata.KeySpec != types.KeySpecEccNistP256 {
			return nil, fmt.Errorf("%s cannot sign with %s",
				metadata.KeySpec, types.SigningAlgorithmSpecEcdsaSha256)
		}
		signature, err = metadata.Signer.Sign(rand.Reader, params.Message, crypto.SHA256)
	case types.SigningAlgorithmSpecEcdsaSha384:
		if metadata.KeySpec != types.KeySpecEccNistP384 {
			return nil, fmt.Errorf("%s cannot sign with %s",
				metadata.KeySpec, types.SigningAlgorithmSpecEcdsaSha384)
		}
		signature, err = metadata.Signer.Sign(rand.Reader, params.Message, crypto.SHA384)
	case types.SigningAlgorithmSpecEcdsaSha512:
		if metadata.KeySpec != types.KeySpecEccNistP521 {
			return nil, fmt.Errorf("%s cannot sign with %s",
				metadata.KeySpec, types.SigningAlgorithmSpecEcdsaSha256)
		}
		signature, err = metadata.Signer.Sign(rand.Reader, params.Message, crypto.SHA512)
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha256:
		signature, err = metadata.Signer.Sign(rand.Reader, params.Message, crypto.SHA256)
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha384:
		signature, err = metadata.Signer.Sign(rand.Reader, params.Message, crypto.SHA384)
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha512:
		signature, err = metadata.Signer.Sign(rand.Reader, params.Message, crypto.SHA512)
	default:
		return nil, fmt.Errorf("unsupported signing algo: %s", params.SigningAlgorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}
	return &kms.SignOutput{
		KeyId:            &metadata.KeyArn,
		Signature:        signature,
		SigningAlgorithm: params.SigningAlgorithm,
	}, nil
}

func (m *mockKMSClient) Decrypt(_ context.Context, params *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if strings.Contains(*params.KeyId, "error-decrypt") {
		return nil, fmt.Errorf("%w: action=decrypt", errForced)
	}
	metadata := m.store[*params.KeyId]

	var plaintext []byte
	var err error

	switch params.EncryptionAlgorithm {
	case types.EncryptionAlgorithmSpecRsaesOaepSha1:
		plaintext, err = metadata.Decrypter.Decrypt(
			rand.Reader, params.CiphertextBlob,
			&rsa.OAEPOptions{
				Hash: crypto.SHA1,
			},
		)
	case types.EncryptionAlgorithmSpecRsaesOaepSha256:
		plaintext, err = metadata.Decrypter.Decrypt(
			rand.Reader, params.CiphertextBlob,
			&rsa.OAEPOptions{
				Hash: crypto.SHA256,
			},
		)
	default:
		return nil, fmt.Errorf("awsmock: unsupported decrypt algo: %s", params.EncryptionAlgorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("awsmock: failed to decrypt: %w", err)
	}
	return &kms.DecryptOutput{
		KeyId:               &metadata.KeyArn,
		Plaintext:           plaintext,
		EncryptionAlgorithm: params.EncryptionAlgorithm,
	}, nil
}
