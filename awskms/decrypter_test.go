package awskms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/tprasadtp/cryptokms"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

func Test_NewDecrypter(t *testing.T) {
	type testCase struct {
		Name      string
		Region    string
		KeyState  types.KeyState
		KeySpec   types.KeySpec
		KeyUsage  types.KeyUsageType
		Client    Client
		Err       error
		Decrypter *Decrypter
	}
	tt := []testCase{
		{
			Name:     "nil-client",
			KeyState: types.KeyStateEnabled,
			Client:   nil,
			KeySpec:  types.KeySpecRsa4096,
			KeyUsage: types.KeyUsageTypeEncryptDecrypt,
			Region:   "us-east-1",
			Err:      cryptokms.ErrInvalidKMSClient,
		},
		// Invalid KeyStateEnabled
		{
			Name:     "error-on-describe",
			KeyState: types.KeyStateEnabled,
			Client:   newMockKMSClient(),
			KeySpec:  types.KeySpecRsa4096,
			KeyUsage: types.KeyUsageTypeEncryptDecrypt,
			Region:   "error-describe",
			Err:      cryptokms.ErrGetKeyMetadata,
		},
		{
			Name:     "key-still-creating",
			KeyState: types.KeyStateCreating,
			Client:   newMockKMSClient(),
			KeySpec:  types.KeySpecRsa4096,
			KeyUsage: types.KeyUsageTypeEncryptDecrypt,
			Region:   "us-east-1",
			Err:      cryptokms.ErrUnusableKeyState,
		},
		{
			Name:     "key-pending-deletion",
			KeyState: types.KeyStatePendingDeletion,
			Client:   newMockKMSClient(),
			KeySpec:  types.KeySpecRsa4096,
			KeyUsage: types.KeyUsageTypeEncryptDecrypt,
			Region:   "us-east-1",
			Err:      cryptokms.ErrUnusableKeyState,
		},
		{
			Name:     "key-disabled",
			KeyState: types.KeyStateDisabled,
			Client:   newMockKMSClient(),
			KeySpec:  types.KeySpecRsa4096,
			KeyUsage: types.KeyUsageTypeEncryptDecrypt,
			Region:   "us-east-1",
			Err:      cryptokms.ErrUnusableKeyState,
		},
		// Invalid Key Usage
		{
			Name:     "key-usage-sign-verify",
			KeyState: types.KeyStateEnabled,
			Client:   newMockKMSClient(),
			KeySpec:  types.KeySpecRsa4096,
			KeyUsage: types.KeyUsageTypeSignVerify,
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
			KeySpec:  types.KeySpecRsa4096,
			KeyUsage: types.KeyUsageTypeEncryptDecrypt,
			Region:   "error-get-public-key",
			Err:      cryptokms.ErrGetKeyMetadata,
		},
		{
			Name:     "unparsable-public-key",
			KeyState: types.KeyStateEnabled,
			Client:   newMockKMSClient(),
			KeySpec:  types.KeySpecRsa4096,
			KeyUsage: types.KeyUsageTypeEncryptDecrypt,
			Region:   "unparsable-public-key",
			Err:      cryptokms.ErrGetKeyMetadata,
		},
		// Valid RSA keys
		{
			Name:     "rsa-2048",
			KeyState: types.KeyStateEnabled,
			Client:   newMockKMSClient(),
			KeySpec:  types.KeySpecRsa2048,
			KeyUsage: types.KeyUsageTypeEncryptDecrypt,
			Region:   "us-east-1",
			Decrypter: &Decrypter{
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
			},
		},
		{
			Name:     "rsa-3072",
			KeyState: types.KeyStateEnabled,
			Client:   newMockKMSClient(),
			KeySpec:  types.KeySpecRsa3072,
			KeyUsage: types.KeyUsageTypeEncryptDecrypt,
			Region:   "us-east-1",
			Decrypter: &Decrypter{
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
			},
		},
		{
			Name:     "rsa-4096",
			KeyState: types.KeyStateEnabled,
			Client:   newMockKMSClient(),
			KeySpec:  types.KeySpecRsa4096,
			KeyUsage: types.KeyUsageTypeEncryptDecrypt,
			Region:   "us-east-1",
			Decrypter: &Decrypter{
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
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()
			arn := computeKMSKeyArn(tc.KeyState, tc.KeySpec, tc.KeyUsage, tc.Region)
			resp, err := NewDecrypter(ctx, tc.Client, arn)
			if !errors.Is(err, tc.Err) {
				t.Errorf("expected error=%+v, but got=%+v", tc.Err, err)
			}
			diff := cmp.Diff(
				resp, tc.Decrypter,
				cmp.AllowUnexported(Decrypter{}),
				cmpopts.IgnoreFields(Decrypter{}, "client", "keyID", "mu"))
			if diff != "" {
				t.Errorf("did not get expected response: \n%s", diff)
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

	if !errors.Is(err, cryptokms.ErrInvalidKMSClient) {
		t.Errorf("expected error=%+v, but got=%+v", cryptokms.ErrInvalidKMSClient, err)
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
		Name          string
		KeyArn        string
		Err           error
		Ciphertext    []byte
		DecrypterOpts crypto.DecrypterOpts
	}

	client := newMockKMSClient()
	tt := []testCase{
		{
			Name: "rsa-4096-oaep-hash-not-equal-to-mgf-hash",
			Ciphertext: func() []byte {
				encrypted, _ := rsa.EncryptOAEP(
					crypto.SHA256.New(), rand.Reader,
					testkeys.GetRSA4096PublicKey(),
					[]byte(testkeys.KnownInput), nil,
				)
				return encrypted
			}(),
			KeyArn: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa4096,
				types.KeyUsageTypeEncryptDecrypt),
			DecrypterOpts: &rsa.OAEPOptions{
				Hash:    crypto.SHA256,
				MGFHash: crypto.SHA1, // should be sha256 or zero value
			},
			Err: cryptokms.ErrDigestAlgorithm,
		},
		{
			Name: "rsa-4096-oaep-ciphertext-too-large",
			Ciphertext: func() []byte {
				buf := make([]byte, 4096/8+1)
				//nolint:errcheck // ignore as test will fail if err != nil
				rand.Reader.Read(buf)
				return buf
			}(),
			KeyArn: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa4096,
				types.KeyUsageTypeEncryptDecrypt),
			DecrypterOpts: &rsa.OAEPOptions{
				Hash: crypto.SHA256,
			},
			Err: cryptokms.ErrPayloadTooLarge,
		},
		{
			Name: "rsa-4096-default-options",
			Ciphertext: func() []byte {
				encrypted, _ := rsa.EncryptOAEP(
					crypto.SHA256.New(), rand.Reader,
					testkeys.GetRSA4096PublicKey(),
					[]byte(testkeys.KnownInput), nil,
				)
				return encrypted
			}(),
			KeyArn: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa4096,
				types.KeyUsageTypeEncryptDecrypt),
		},
		{
			Name: "rsa-4096-valid-options",
			Ciphertext: func() []byte {
				encrypted, _ := rsa.EncryptOAEP(
					crypto.SHA256.New(), rand.Reader,
					testkeys.GetRSA4096PublicKey(),
					[]byte(testkeys.KnownInput), nil,
				)
				return encrypted
			}(),
			DecrypterOpts: &rsa.OAEPOptions{
				Hash: crypto.SHA256,
			},
			KeyArn: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa4096,
				types.KeyUsageTypeEncryptDecrypt),
		},
		{
			Name: "rsa-4096-sha1",
			Ciphertext: func() []byte {
				encrypted, _ := rsa.EncryptOAEP(
					crypto.SHA1.New(), rand.Reader,
					testkeys.GetRSA4096PublicKey(),
					[]byte(testkeys.KnownInput), nil,
				)
				return encrypted
			}(),
			DecrypterOpts: &rsa.OAEPOptions{
				Hash: crypto.SHA1,
			},
			KeyArn: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa4096,
				types.KeyUsageTypeEncryptDecrypt),
		},
		{
			Name: "rsa-4096-sha512-unsupported",
			Ciphertext: func() []byte {
				encrypted, _ := rsa.EncryptOAEP(
					crypto.SHA512.New(), rand.Reader,
					testkeys.GetRSA4096PublicKey(),
					[]byte(testkeys.KnownInput), nil,
				)
				return encrypted
			}(),
			DecrypterOpts: &rsa.OAEPOptions{
				Hash: crypto.SHA512,
			},
			KeyArn: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa4096,
				types.KeyUsageTypeEncryptDecrypt),
			Err: cryptokms.ErrDigestAlgorithm,
		},
		{
			Name: "rsa-4096-PKCS1v15DecryptOptions-unsupported",
			Ciphertext: func() []byte {
				encrypted, _ := rsa.EncryptOAEP(
					crypto.SHA256.New(), rand.Reader,
					testkeys.GetRSA4096PublicKey(),
					[]byte(testkeys.KnownInput), nil,
				)
				return encrypted
			}(),
			DecrypterOpts: &rsa.PKCS1v15DecryptOptions{},
			KeyArn: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa4096,
				types.KeyUsageTypeEncryptDecrypt),
			Err: cryptokms.ErrAsymmetricDecrypt,
		},
		{
			Name: "rsa-4096-unsupported-type",
			Ciphertext: func() []byte {
				encrypted, _ := rsa.EncryptOAEP(
					crypto.SHA256.New(), rand.Reader,
					testkeys.GetRSA4096PublicKey(),
					[]byte(testkeys.KnownInput), nil,
				)
				return encrypted
			}(),
			DecrypterOpts: rsa.OAEPOptions{Hash: crypto.SHA256}, // should be pointer
			KeyArn: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa4096,
				types.KeyUsageTypeEncryptDecrypt),
			Err: cryptokms.ErrAsymmetricDecrypt,
		},
		{
			Name: "rsa-4096-error-on-decrypt-api-call",
			Ciphertext: func() []byte {
				encrypted, _ := rsa.EncryptOAEP(
					crypto.SHA256.New(), rand.Reader,
					testkeys.GetRSA4096PublicKey(),
					[]byte(testkeys.KnownInput), nil,
				)
				return encrypted
			}(),
			KeyArn: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa4096,
				types.KeyUsageTypeEncryptDecrypt,
				"error-decrypt"),
			Err: cryptokms.ErrAsymmetricDecrypt,
		},
		{
			Name: "rsa-3072-sha256",
			Ciphertext: func() []byte {
				encrypted, _ := rsa.EncryptOAEP(
					crypto.SHA256.New(), rand.Reader,
					testkeys.GetRSA3072PublicKey(),
					[]byte(testkeys.KnownInput), nil,
				)
				return encrypted
			}(),
			KeyArn: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa3072,
				types.KeyUsageTypeEncryptDecrypt),
		},
		{
			Name: "rsa-2048-sha256",
			Ciphertext: func() []byte {
				encrypted, _ := rsa.EncryptOAEP(
					crypto.SHA256.New(), rand.Reader,
					testkeys.GetRSA2048PublicKey(),
					[]byte(testkeys.KnownInput), nil,
				)
				return encrypted
			}(),
			KeyArn: computeKMSKeyArn(
				types.KeyStateEnabled,
				types.KeySpecRsa2048,
				types.KeyUsageTypeEncryptDecrypt),
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()
			decrypter, err := NewDecrypter(ctx, client, tc.KeyArn)
			if err != nil {
				t.Fatalf("failed to build decrypter(%s): %s", tc.KeyArn, err)
			}

			if err != nil {
				t.Fatalf("failed to encrypt: %s", err)
			}
			plaintext, err := decrypter.Decrypt(
				rand.Reader,
				tc.Ciphertext,
				tc.DecrypterOpts,
			)

			if !errors.Is(err, tc.Err) {
				t.Fatalf("expected err=%s, got err=%s", tc.Err, err)
			}

			if tc.Err == nil {
				if string(plaintext) != testkeys.KnownInput {
					t.Errorf("expected plaintext=%s, got=%s", testkeys.KnownInput, plaintext)
				}
			}

			// ensure created at is not zero time
			if decrypter.CreatedAt().IsZero() {
				t.Errorf("CreatedAt() must not be zero")
			}
		})
	}
}
