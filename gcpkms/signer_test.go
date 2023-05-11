package gcpkms

import (
	"context"
	"crypto"
	"crypto/rand"
	"errors"
	"testing"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/tprasadtp/cryptokms"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func Test_NewSigner(t *testing.T) {
	type testCase struct {
		Name        string
		KeyID       string
		Client      *kms.KeyManagementClient
		Response    *Signer
		ResponseErr error
	}

	server := newFakeServer(t)
	server.Serve(t)
	client := server.Client(t)

	tt := []testCase{
		{
			Name:        "nil-client",
			KeyID:       "IGNORED_VALUE",
			ResponseErr: cryptokms.ErrInvalidKMSClient,
		},
		{
			Name:        "force-error-response-on-GetCryptoKeyVersion",
			Client:      client,
			KeyID:       "ERROR_GET_CRYPTOKEY_VERSION",
			ResponseErr: cryptokms.ErrGetKeyMetadata,
		},
		{
			Name:        "destroyed-key",
			Client:      client,
			KeyID:       "DESTROYED_RSA_SIGN_PKCS1_2048_SHA256",
			ResponseErr: cryptokms.ErrUnusableKeyState,
		},
		{
			Name:        "unsupported-key-secp256k1",
			Client:      client,
			KeyID:       "EC_SIGN_SECP256K1_SHA256",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		// HMAC Keys
		{
			Name:        "unsupported-key-hmac-sha1",
			Client:      client,
			KeyID:       "HMAC_SHA1",
			ResponseErr: cryptokms.ErrUnsupportedMethod,
		},
		{
			Name:        "unsupported-key-hmac-sha224",
			Client:      client,
			KeyID:       "HMAC_SHA224",
			ResponseErr: cryptokms.ErrUnsupportedMethod,
		},
		{
			Name:        "unsupported-key-hmac-sha256",
			Client:      client,
			KeyID:       "HMAC_SHA256",
			ResponseErr: cryptokms.ErrUnsupportedMethod,
		},
		{
			Name:        "unsupported-key-hmac-sha384",
			Client:      client,
			KeyID:       "HMAC_SHA384",
			ResponseErr: cryptokms.ErrUnsupportedMethod,
		},
		{
			Name:        "unsupported-key-hmac-sha512",
			Client:      client,
			KeyID:       "HMAC_SHA512",
			ResponseErr: cryptokms.ErrUnsupportedMethod,
		},
		// symmetric keys
		{
			Name:        "unsupported-key-google-symmetric",
			Client:      client,
			KeyID:       "GOOGLE_SYMMETRIC_ENCRYPTION",
			ResponseErr: cryptokms.ErrUnsupportedMethod,
		},
		{
			Name:        "unsupported-key-encryption-rsa2048-sha1",
			Client:      client,
			KeyID:       "RSA_DECRYPT_OAEP_2048_SHA1",
			ResponseErr: cryptokms.ErrUnsupportedMethod,
		},
		{
			Name:        "unsupported-key-encryption-rsa3072-sha1",
			Client:      client,
			KeyID:       "RSA_DECRYPT_OAEP_3072_SHA1",
			ResponseErr: cryptokms.ErrUnsupportedMethod,
		},
		{
			Name:        "unsupported-key-encryption-rsa4096-sha1",
			Client:      client,
			KeyID:       "RSA_DECRYPT_OAEP_4096_SHA1",
			ResponseErr: cryptokms.ErrUnsupportedMethod,
		},
		// SHA256
		{
			Name:        "unsupported-key-encryption-rsa2048-sha256",
			Client:      client,
			KeyID:       "RSA_DECRYPT_OAEP_2048_SHA256",
			ResponseErr: cryptokms.ErrUnsupportedMethod,
		},
		{
			Name:        "unsupported-key-encryption-rsa3072-sha256",
			Client:      client,
			KeyID:       "RSA_DECRYPT_OAEP_3072_SHA256",
			ResponseErr: cryptokms.ErrUnsupportedMethod,
		},
		{
			Name:        "unsupported-key-encryption-rsa4096-sha256",
			Client:      client,
			KeyID:       "RSA_DECRYPT_OAEP_4096_SHA256",
			ResponseErr: cryptokms.ErrUnsupportedMethod,
		},
		{
			Name:        "unsupported-key-encryption-rsa4096-sha512",
			Client:      client,
			KeyID:       "RSA_DECRYPT_OAEP_4096_SHA512",
			ResponseErr: cryptokms.ErrUnsupportedMethod,
		},
		// unknown key
		{
			Name:        "unsupported-key-external-symmetric-encryption",
			Client:      client,
			KeyID:       "EXTERNAL_SYMMETRIC_ENCRYPTION",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "error-srv-rsa-pss-2048-sha256",
			Client:      client,
			KeyID:       "RSA_SIGN_PSS_2048_SHA256",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "error-srv-rsa-pss-3072-sha256",
			Client:      client,
			KeyID:       "RSA_SIGN_PSS_3072_SHA256",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "error-srv-rsa-pss-4096-sha256",
			Client:      client,
			KeyID:       "RSA_SIGN_PSS_4096_SHA256",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "error-srv-rsa-pss-4096-sha512",
			Client:      client,
			KeyID:       "RSA_SIGN_PSS_4096_SHA512",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		// get key corrupted response
		{
			Name:        "integrity-invalid-rsa-sign-pkcs1-2048-sha256",
			Client:      client,
			KeyID:       "ERROR_SRV_INTEGRITY_RSA_SIGN_PKCS1_2048_SHA256",
			ResponseErr: ErrResponseIntegrity,
		},
		{
			Name:        "integrity-invalid-rsa-sign-pkcs1-3072-sha256",
			Client:      client,
			KeyID:       "ERROR_SRV_INTEGRITY_RSA_SIGN_PKCS1_3072_SHA256",
			ResponseErr: ErrResponseIntegrity,
		},
		{
			Name:        "integrity-invalid-rsa-sign-pkcs1-4096-sha256",
			Client:      client,
			KeyID:       "ERROR_SRV_INTEGRITY_RSA_SIGN_PKCS1_4096_SHA256",
			ResponseErr: ErrResponseIntegrity,
		},
		{
			Name:        "integrity-invalid-rsa-sign-pkcs1-4096-sha512",
			Client:      client,
			KeyID:       "ERROR_SRV_INTEGRITY_RSA_SIGN_PKCS1_4096_SHA512",
			ResponseErr: ErrResponseIntegrity,
		},
		{
			Name:        "integrity-invalid-ec-sign-p256-sha256",
			Client:      client,
			KeyID:       "ERROR_SRV_INTEGRITY_EC_SIGN_P256_SHA256",
			ResponseErr: ErrResponseIntegrity,
		},
		{
			Name:        "integrity-invalid-ec-sign-p384-sha384",
			Client:      client,
			KeyID:       "ERROR_SRV_INTEGRITY_EC_SIGN_P384_SHA384",
			ResponseErr: ErrResponseIntegrity,
		},
		// GetPublicKey returns an error.
		{
			Name:        "error-on-GetPublicKey",
			Client:      client,
			KeyID:       "ERROR_ON_GET_PUBLICKEY_EC_SIGN_P256_SHA256",
			ResponseErr: status.Error(codes.Internal, "fake service error"),
		},
		// Returns RSA Signer
		{
			Name:   "valid-RSA_SIGN_PKCS1_2048_SHA256",
			Client: client,
			KeyID:  "RSA_SIGN_PKCS1_2048_SHA256",
			Response: &Signer{
				name:   "RSA_SIGN_PKCS1_2048_SHA256",
				hash:   crypto.SHA256,
				ctime:  knownTS,
				client: client,
				pub:    &testkeys.GetRSA2048PrivateKey().PublicKey,
			},
		},
		{
			Name:   "valid-RSA_SIGN_PKCS1_3072_SHA256",
			Client: client,
			KeyID:  "RSA_SIGN_PKCS1_3072_SHA256",
			Response: &Signer{
				name:   "RSA_SIGN_PKCS1_3072_SHA256",
				hash:   crypto.SHA256,
				ctime:  knownTS,
				client: client,
				pub:    &testkeys.GetRSA3072PrivateKey().PublicKey,
			},
		},
		{
			Name:   "valid-RSA_SIGN_PKCS1_4096_SHA256",
			Client: client,
			KeyID:  "RSA_SIGN_PKCS1_4096_SHA256",
			Response: &Signer{
				name:   "RSA_SIGN_PKCS1_4096_SHA256",
				hash:   crypto.SHA256,
				ctime:  knownTS,
				client: client,
				pub:    &testkeys.GetRSA4096PrivateKey().PublicKey,
			},
		},
		{
			Name:   "valid-RSA_SIGN_PKCS1_4096_SHA512",
			Client: client,
			KeyID:  "RSA_SIGN_PKCS1_4096_SHA512",
			Response: &Signer{
				name:   "RSA_SIGN_PKCS1_4096_SHA512",
				hash:   crypto.SHA512,
				ctime:  knownTS,
				client: client,
				pub:    &testkeys.GetRSA4096PrivateKey().PublicKey,
			},
		},
		{
			Name:   "valid-EC_SIGN_P256_SHA256",
			Client: client,
			KeyID:  "EC_SIGN_P256_SHA256",
			Response: &Signer{
				name:   "EC_SIGN_P256_SHA256",
				hash:   crypto.SHA256,
				ctime:  knownTS,
				client: client,
				pub:    &testkeys.GetECP256PrivateKey().PublicKey,
			},
		},
		{
			Name:   "valid-EC_SIGN_P384_SHA384",
			Client: client,
			KeyID:  "EC_SIGN_P384_SHA384",
			Response: &Signer{
				name:   "EC_SIGN_P384_SHA384",
				hash:   crypto.SHA384,
				ctime:  knownTS,
				client: client,
				pub:    &testkeys.GetECP384PrivateKey().PublicKey,
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()
			resp, err := NewSigner(ctx, tc.Client, tc.KeyID)
			if !errors.Is(err, tc.ResponseErr) {
				t.Errorf("expected error=%+v, but got=%+v", tc.ResponseErr, err)
			}
			diff := cmp.Diff(
				resp, tc.Response,
				cmp.AllowUnexported(Signer{}),
				cmpopts.IgnoreFields(Signer{}, "client", "mu"))
			if diff != "" {
				t.Errorf("did not get expected response: \n%s", diff)
			}

			if resp.Backend() != cryptokms.BackendGoogleCloudKMS {
				t.Errorf("expected Backend=%v, got=%v", cryptokms.BackendGoogleCloudKMS, resp.Backend())
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

	if !errors.Is(err, cryptokms.ErrInvalidKMSClient) {
		t.Errorf("expected error=%+v, but got=%+v", cryptokms.ErrInvalidKMSClient, err)
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
		Name        string
		Digest      []byte
		Options     crypto.SignerOpts
		KeyID       string
		ResponseErr error
	}

	server := newFakeServer(t)
	server.Serve(t)
	client := server.Client(t)

	tt := []testCase{
		{
			Name:        "digest-algorithm-mismatch-1",
			KeyID:       "RSA_SIGN_PKCS1_2048_SHA256",
			Options:     crypto.SHA1, // should be sha256
			Digest:      testkeys.KnownInputHash(crypto.SHA1),
			ResponseErr: cryptokms.ErrDigestAlgorithm,
		},
		{
			Name:        "digest-length-mismatch-1",
			KeyID:       "RSA_SIGN_PKCS1_2048_SHA256",
			Options:     crypto.SHA256,
			Digest:      testkeys.KnownInputHash(crypto.SHA1), // should be sha256 hash
			ResponseErr: cryptokms.ErrDigestLength,
		},
		{
			Name:        "error-on-sign",
			KeyID:       "RSA_SIGN_PKCS1_2048_SHA256_FORCE_ERROR_ON_ASYMMETRICSIGN",
			Options:     crypto.SHA256,
			Digest:      testkeys.KnownInputHash(crypto.SHA256),
			ResponseErr: cryptokms.ErrAsymmetricSign,
		},
		{
			Name:        "error-req-integrity",
			KeyID:       "RSA_SIGN_PKCS1_2048_SHA256_ERROR_REQ_INTEGRITY",
			Options:     crypto.SHA256,
			Digest:      testkeys.KnownInputHash(crypto.SHA256),
			ResponseErr: ErrRequestIntegrity,
		},
		{
			Name:        "error-resp-integrity",
			KeyID:       "RSA_SIGN_PKCS1_2048_SHA256_ERROR_RESP_INTEGRITY",
			Options:     crypto.SHA256,
			Digest:      testkeys.KnownInputHash(crypto.SHA256),
			ResponseErr: ErrResponseIntegrity,
		},
		{
			Name:    "RSA_SIGN_PKCS1_2048_SHA256",
			KeyID:   "RSA_SIGN_PKCS1_2048_SHA256",
			Options: crypto.SHA256,
			Digest:  testkeys.KnownInputHash(crypto.SHA256),
		},
		{
			Name:    "RSA_SIGN_PKCS1_3072_SHA256",
			KeyID:   "RSA_SIGN_PKCS1_3072_SHA256",
			Options: crypto.SHA256,
			Digest:  testkeys.KnownInputHash(crypto.SHA256),
		},
		{
			Name:    "RSA_SIGN_PKCS1_4096_SHA256",
			KeyID:   "RSA_SIGN_PKCS1_4096_SHA256",
			Options: crypto.SHA256,
			Digest:  testkeys.KnownInputHash(crypto.SHA256),
		},
		{
			Name:    "RSA_SIGN_PKCS1_4096_SHA512",
			KeyID:   "RSA_SIGN_PKCS1_4096_SHA512",
			Options: crypto.SHA512,
			Digest:  testkeys.KnownInputHash(crypto.SHA512),
		},
		// WithoutOptions
		{
			Name:   "RSA_SIGN_PKCS1_2048_SHA256-WithoutOptions",
			KeyID:  "RSA_SIGN_PKCS1_2048_SHA256",
			Digest: testkeys.KnownInputHash(crypto.SHA256),
		},
		{
			Name:   "RSA_SIGN_PKCS1_3072_SHA256-WithoutOptions",
			KeyID:  "RSA_SIGN_PKCS1_3072_SHA256",
			Digest: testkeys.KnownInputHash(crypto.SHA256),
		},
		{
			Name:   "RSA_SIGN_PKCS1_4096_SHA256-WithoutOptions",
			KeyID:  "RSA_SIGN_PKCS1_4096_SHA256",
			Digest: testkeys.KnownInputHash(crypto.SHA256),
		},
		{
			Name:   "RSA_SIGN_PKCS1_4096_SHA512-WithoutOptions",
			KeyID:  "RSA_SIGN_PKCS1_4096_SHA512",
			Digest: testkeys.KnownInputHash(crypto.SHA512),
		},
		// ECC Keys
		{
			Name:    "EC_SIGN_P256_SHA256",
			KeyID:   "EC_SIGN_P256_SHA256",
			Options: crypto.SHA256,
			Digest:  testkeys.KnownInputHash(crypto.SHA256),
		},
		{
			Name:    "EC_SIGN_P384_SHA384",
			KeyID:   "EC_SIGN_P384_SHA384",
			Options: crypto.SHA384,
			Digest:  testkeys.KnownInputHash(crypto.SHA384),
		},
		// Without Options
		{
			Name:   "EC_SIGN_P256_SHA256",
			KeyID:  "EC_SIGN_P256_SHA256",
			Digest: testkeys.KnownInputHash(crypto.SHA256),
		},
		{
			Name:   "EC_SIGN_P384_SHA384",
			KeyID:  "EC_SIGN_P384_SHA384",
			Digest: testkeys.KnownInputHash(crypto.SHA384),
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()
			signer, err := NewSigner(ctx, client, tc.KeyID)
			if err != nil {
				t.Fatalf("failed to build signer - %s: %s", tc.KeyID, err)
			}

			signature, err := signer.Sign(
				rand.Reader,
				tc.Digest,
				tc.Options,
			)

			if !errors.Is(err, tc.ResponseErr) {
				t.Fatalf("expected err=%s, got err=%s", tc.ResponseErr, err)
			}

			// Verify signature
			if tc.ResponseErr == nil {
				err = cryptokms.VerifyDigestSignature(
					signer.Public(),
					signer.HashFunc(),
					tc.Digest, signature)
				if err != nil {
					t.Errorf("signature verification failed: %s", err)
				}
			}
		})
	}
}
