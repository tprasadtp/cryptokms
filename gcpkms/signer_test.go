package gcpkms

import (
	"context"
	"crypto"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/tprasadtp/cryptokms"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNewSigner(t *testing.T) {
	type testCase struct {
		Name        string
		KeyID       string
		Response    *Signer
		ResponseErr error
	}

	server := newFakeServer(t)
	server.Serve(t)
	clientOptions := server.Options(t)

	tt := []testCase{
		{
			Name:        "force-error-response-on-GetCryptoKeyVersion",
			KeyID:       "ERROR_GET_CRYPTOKEY_VERSION",
			ResponseErr: cryptokms.ErrGetKeyMetadata,
		},
		{
			Name:        "destroyed-key",
			KeyID:       "DESTROYED_RSA_SIGN_PKCS1_2048_SHA256",
			ResponseErr: cryptokms.ErrUnusableKeyState,
		},
		{
			Name:        "unsupported-key-secp256k1",
			KeyID:       "EC_SIGN_SECP256K1_SHA256",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		// HMAC Keys
		{
			Name:        "unsupported-key-hmac-sha1",
			KeyID:       "HMAC_SHA1",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "unsupported-key-hmac-sha224",
			KeyID:       "HMAC_SHA224",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "unsupported-key-hmac-sha256",
			KeyID:       "HMAC_SHA256",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "unsupported-key-hmac-sha384",
			KeyID:       "HMAC_SHA384",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "unsupported-key-hmac-sha512",
			KeyID:       "HMAC_SHA512",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		// symmetric keys
		{
			Name:        "unsupported-key-google-symmetric",
			KeyID:       "GOOGLE_SYMMETRIC_ENCRYPTION",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "unsupported-key-encryption-rsa2048-sha1",
			KeyID:       "RSA_DECRYPT_OAEP_2048_SHA1",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "unsupported-key-encryption-rsa3072-sha1",
			KeyID:       "RSA_DECRYPT_OAEP_3072_SHA1",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "unsupported-key-encryption-rsa4096-sha1",
			KeyID:       "RSA_DECRYPT_OAEP_4096_SHA1",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		// SHA256
		{
			Name:        "unsupported-key-encryption-rsa2048-sha256",
			KeyID:       "RSA_DECRYPT_OAEP_2048_SHA256",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "unsupported-key-encryption-rsa3072-sha256",
			KeyID:       "RSA_DECRYPT_OAEP_3072_SHA256",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "unsupported-key-encryption-rsa4096-sha256",
			KeyID:       "RSA_DECRYPT_OAEP_4096_SHA256",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "unsupported-key-encryption-rsa4096-sha512",
			KeyID:       "RSA_DECRYPT_OAEP_4096_SHA512",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		// unknown key
		{
			Name:        "unsupported-key-external-symmetric-encryption",
			KeyID:       "EXTERNAL_SYMMETRIC_ENCRYPTION",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "error-srv-rsa-pss-2048-sha256",
			KeyID:       "RSA_SIGN_PSS_2048_SHA256",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "error-srv-rsa-pss-3072-sha256",
			KeyID:       "RSA_SIGN_PSS_3072_SHA256",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "error-srv-rsa-pss-4096-sha256",
			KeyID:       "RSA_SIGN_PSS_4096_SHA256",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "error-srv-rsa-pss-4096-sha512",
			KeyID:       "RSA_SIGN_PSS_4096_SHA512",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		// get key corrupted response
		{
			Name:        "integrity-invalid-rsa-sign-pkcs1-2048-sha256",
			KeyID:       "ERROR_SRV_INTEGRITY_RSA_SIGN_PKCS1_2048_SHA256",
			ResponseErr: ErrResponseIntegrity,
		},
		{
			Name:        "integrity-invalid-rsa-sign-pkcs1-3072-sha256",
			KeyID:       "ERROR_SRV_INTEGRITY_RSA_SIGN_PKCS1_3072_SHA256",
			ResponseErr: ErrResponseIntegrity,
		},
		{
			Name:        "integrity-invalid-rsa-sign-pkcs1-4096-sha256",
			KeyID:       "ERROR_SRV_INTEGRITY_RSA_SIGN_PKCS1_4096_SHA256",
			ResponseErr: ErrResponseIntegrity,
		},
		{
			Name:        "integrity-invalid-rsa-sign-pkcs1-4096-sha512",
			KeyID:       "ERROR_SRV_INTEGRITY_RSA_SIGN_PKCS1_4096_SHA512",
			ResponseErr: ErrResponseIntegrity,
		},
		{
			Name:        "integrity-invalid-ec-sign-p256-sha256",
			KeyID:       "ERROR_SRV_INTEGRITY_EC_SIGN_P256_SHA256",
			ResponseErr: ErrResponseIntegrity,
		},
		{
			Name:        "integrity-invalid-ec-sign-p384-sha384",
			KeyID:       "ERROR_SRV_INTEGRITY_EC_SIGN_P384_SHA384",
			ResponseErr: ErrResponseIntegrity,
		},
		// GetPublicKey returns an error.
		{
			Name:        "error-on-GetPublicKey",
			KeyID:       "ERROR_ON_GET_PUBLICKEY_EC_SIGN_P256_SHA256",
			ResponseErr: status.Error(codes.Internal, "fake service error"),
		},
		// Returns RSA Signer
		{
			Name:  "valid-RSA_SIGN_PKCS1_2048_SHA256",
			KeyID: "RSA_SIGN_PKCS1_2048_SHA256",
			Response: &Signer{
				name:  "RSA_SIGN_PKCS1_2048_SHA256",
				hash:  crypto.SHA256,
				ctime: knownTS,
				pub:   &testkeys.GetRSA2048PrivateKey().PublicKey,
				algo:  cryptokms.AlgorithmRSA2048,
			},
		},
		{
			Name:  "valid-RSA_SIGN_PKCS1_3072_SHA256",
			KeyID: "RSA_SIGN_PKCS1_3072_SHA256",
			Response: &Signer{
				name:  "RSA_SIGN_PKCS1_3072_SHA256",
				hash:  crypto.SHA256,
				ctime: knownTS,
				pub:   &testkeys.GetRSA3072PrivateKey().PublicKey,
				algo:  cryptokms.AlgorithmRSA3072,
			},
		},
		{
			Name:  "valid-RSA_SIGN_PKCS1_4096_SHA256",
			KeyID: "RSA_SIGN_PKCS1_4096_SHA256",
			Response: &Signer{
				name:  "RSA_SIGN_PKCS1_4096_SHA256",
				hash:  crypto.SHA256,
				ctime: knownTS,
				pub:   &testkeys.GetRSA4096PrivateKey().PublicKey,
				algo:  cryptokms.AlgorithmRSA4096,
			},
		},
		{
			Name:  "valid-RSA_SIGN_PKCS1_4096_SHA512",
			KeyID: "RSA_SIGN_PKCS1_4096_SHA512",
			Response: &Signer{
				name:  "RSA_SIGN_PKCS1_4096_SHA512",
				hash:  crypto.SHA512,
				ctime: knownTS,
				pub:   &testkeys.GetRSA4096PrivateKey().PublicKey,
				algo:  cryptokms.AlgorithmRSA4096,
			},
		},
		{
			Name:  "valid-EC_SIGN_P256_SHA256",
			KeyID: "EC_SIGN_P256_SHA256",
			Response: &Signer{
				name:  "EC_SIGN_P256_SHA256",
				hash:  crypto.SHA256,
				ctime: knownTS,
				pub:   &testkeys.GetECP256PrivateKey().PublicKey,
				algo:  cryptokms.AlgorithmECP256,
			},
		},
		{
			Name:  "valid-EC_SIGN_P384_SHA384",
			KeyID: "EC_SIGN_P384_SHA384",
			Response: &Signer{
				name:  "EC_SIGN_P384_SHA384",
				hash:  crypto.SHA384,
				ctime: knownTS,
				pub:   &testkeys.GetECP384PrivateKey().PublicKey,
				algo:  cryptokms.AlgorithmECP384,
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()
			resp, err := NewSigner(ctx, tc.KeyID, clientOptions...)
			if !errors.Is(err, tc.ResponseErr) {
				t.Errorf("expected error=%#v, but got=%#v", tc.ResponseErr, err)
			}
			diff := cmp.Diff(
				resp, tc.Response,
				cmp.AllowUnexported(Signer{}),
				cmpopts.IgnoreFields(Signer{}, "client", "mu"))
			if diff != "" {
				t.Errorf("did not get expected response: \n%s", diff)
			}

			if tc.ResponseErr == nil {
				if resp.Algorithm() != tc.Response.algo {
					t.Errorf("expected algo=%d, got=%d", tc.Response.algo, resp.Algorithm())
				}
			}
		})
	}
}

func TestNewSigner_ClientBuildError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewSigner(ctx, "IGNORED_VALUE")
	if !errors.Is(err, cryptokms.ErrInvalidKMSClient) {
		t.Errorf("expected error(ErrInvalidKMSClient) when ctx is already cancelled")
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
	clientOptions := server.Options(t)

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
			signer, err := NewSigner(ctx, tc.KeyID, clientOptions...)
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
