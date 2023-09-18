package gcpkms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
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

func Test_Decrypter(t *testing.T) {
	type testCase struct {
		Name        string
		KeyID       string
		Client      *kms.KeyManagementClient
		Response    *Decrypter
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
			KeyID:       "DESTROYED_RSA_DECRYPT_OAEP_4096_SHA1",
			ResponseErr: cryptokms.ErrUnusableKeyState,
		},
		{
			Name:        "unsupported-key-secp256k1",
			KeyID:       "EC_SIGN_SECP256K1_SHA256",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		// HMAC Keys are unsupported for decryption.
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
		// symmetric keys are unsupported for asymmetric decryption.
		{
			Name:        "unsupported-key-google-symmetric",
			KeyID:       "GOOGLE_SYMMETRIC_ENCRYPTION",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		// PSS Signing Keys are unsupported for asymmetric decryption.
		{
			Name:        "unsupported-RSA_SIGN_PSS_2048_SHA256",
			KeyID:       "RSA_SIGN_PSS_2048_SHA256",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "unsupported-RSA_SIGN_PSS_3072_SHA256",
			KeyID:       "RSA_SIGN_PSS_3072_SHA256",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "unsupported-RSA_SIGN_PSS_4096_SHA256",
			KeyID:       "RSA_SIGN_PSS_4096_SHA256",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "unsupported-RSA_SIGN_PSS_4096_SHA512",
			KeyID:       "RSA_SIGN_PSS_4096_SHA512",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		// get public key returns corrupted response
		{
			Name:        "integrity-invalid-RSA_DECRYPT_OAEP_2048_SHA1",
			KeyID:       "ERROR_SRV_INTEGRITY_RSA_DECRYPT_OAEP_2048_SHA1",
			ResponseErr: ErrResponseIntegrity,
		},
		// GetPublicKey returns an error.
		{
			Name:        "error-on-GetPublicKey",
			KeyID:       "ERROR_ON_GET_PUBLICKEY_RSA_DECRYPT_OAEP_2048_SHA1",
			ResponseErr: status.Error(codes.Internal, "fake service error"),
		},
		// Returns RSA Decrypter
		{
			Name:  "valid-RSA_DECRYPT_OAEP_2048_SHA1",
			KeyID: "RSA_DECRYPT_OAEP_2048_SHA1",
			Response: &Decrypter{
				name:  "RSA_DECRYPT_OAEP_2048_SHA1",
				hash:  crypto.SHA1,
				ctime: knownTS,
				algo:  cryptokms.AlgorithmRSA2048,
				pub:   &testkeys.GetRSA2048PrivateKey().PublicKey,
			},
		},
		{
			Name:  "valid-RSA_DECRYPT_OAEP_3072_SHA1",
			KeyID: "RSA_DECRYPT_OAEP_3072_SHA1",
			Response: &Decrypter{
				name:  "RSA_DECRYPT_OAEP_3072_SHA1",
				hash:  crypto.SHA1,
				ctime: knownTS,
				pub:   &testkeys.GetRSA3072PrivateKey().PublicKey,
				algo:  cryptokms.AlgorithmRSA3072,
			},
		},
		{
			Name:  "valid-RSA_DECRYPT_OAEP_4096_SHA1",
			KeyID: "RSA_DECRYPT_OAEP_4096_SHA1",
			Response: &Decrypter{
				name:  "RSA_DECRYPT_OAEP_4096_SHA1",
				hash:  crypto.SHA1,
				ctime: knownTS,
				algo:  cryptokms.AlgorithmRSA4096,
				pub:   &testkeys.GetRSA4096PrivateKey().PublicKey,
			},
		},
		// SHA256
		{
			Name:  "valid-RSA_DECRYPT_OAEP_2048_SHA256",
			KeyID: "RSA_DECRYPT_OAEP_2048_SHA256",
			Response: &Decrypter{
				name:  "RSA_DECRYPT_OAEP_2048_SHA256",
				hash:  crypto.SHA256,
				ctime: knownTS,
				algo:  cryptokms.AlgorithmRSA2048,
				pub:   &testkeys.GetRSA2048PrivateKey().PublicKey,
			},
		},
		{
			Name:  "valid-RSA_DECRYPT_OAEP_3072_SHA256",
			KeyID: "RSA_DECRYPT_OAEP_3072_SHA256",
			Response: &Decrypter{
				name:  "RSA_DECRYPT_OAEP_3072_SHA256",
				hash:  crypto.SHA256,
				ctime: knownTS,
				algo:  cryptokms.AlgorithmRSA3072,
				pub:   &testkeys.GetRSA3072PrivateKey().PublicKey,
			},
		},
		{
			Name:  "valid-RSA_DECRYPT_OAEP_4096_SHA256",
			KeyID: "RSA_DECRYPT_OAEP_4096_SHA256",
			Response: &Decrypter{
				name:  "RSA_DECRYPT_OAEP_4096_SHA256",
				hash:  crypto.SHA256,
				ctime: knownTS,
				algo:  cryptokms.AlgorithmRSA4096,
				pub:   &testkeys.GetRSA4096PrivateKey().PublicKey,
			},
		},
		{
			Name:  "valid-RSA_DECRYPT_OAEP_4096_SHA512",
			KeyID: "RSA_DECRYPT_OAEP_4096_SHA512",
			Response: &Decrypter{
				name:  "RSA_DECRYPT_OAEP_4096_SHA512",
				hash:  crypto.SHA512,
				ctime: knownTS,
				algo:  cryptokms.AlgorithmRSA4096,
				pub:   &testkeys.GetRSA4096PrivateKey().PublicKey,
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()
			resp, err := NewDecrypter(ctx, tc.KeyID, clientOptions...)
			if !errors.Is(err, tc.ResponseErr) {
				t.Errorf("expected error=%v, but got=%v", tc.ResponseErr, err)
			}
			diff := cmp.Diff(
				resp, tc.Response,
				cmp.AllowUnexported(Decrypter{}),
				cmpopts.IgnoreFields(Decrypter{}, "client", "mu"))
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

func TestNewDecrypter_ClientBuildError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewDecrypter(ctx, "IGNORED_VALUE")
	if !errors.Is(err, cryptokms.ErrInvalidKMSClient) {
		t.Errorf("expected error(ErrInvalidKMSClient) when ctx is already cancelled")
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
		t.Errorf("expected error=%v, but got=%v", cryptokms.ErrInvalidKMSClient, err)
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
		KeyID         string
		ResponseErr   error
		DecrypterOpts any
	}

	server := newFakeServer(t)
	server.Serve(t)
	clientOptions := server.Options(t)

	tt := []testCase{
		{
			Name:        "error-on-sign",
			KeyID:       "FORCE_ERROR_ON_ASYMMETRICDECTYPT_RSA_DECRYPT_OAEP_2048_SHA256",
			ResponseErr: cryptokms.ErrAsymmetricDecrypt,
		},
		{
			Name:        "error-request-integrity",
			KeyID:       "ERROR_REQ_INTEGRITY_RSA_DECRYPT_OAEP_2048_SHA256",
			ResponseErr: ErrRequestIntegrity,
		},
		{
			Name:        "error-response-integrity",
			KeyID:       "ERROR_RESP_INTEGRITY_RSA_DECRYPT_OAEP_2048_SHA256",
			ResponseErr: ErrResponseIntegrity,
		},
		{
			Name: "error-mismatch-options-hash",
			DecrypterOpts: &rsa.OAEPOptions{
				Hash: crypto.SHA1, // should be SHA256
			},
			ResponseErr: cryptokms.ErrDigestAlgorithm,
			KeyID:       "RSA_DECRYPT_OAEP_2048_SHA256",
		},
		{
			Name: "error-mismatch-options-type",
			DecrypterOpts: rsa.OAEPOptions{ // should be pointer
				Hash: crypto.SHA256,
			},
			ResponseErr: cryptokms.ErrAsymmetricDecrypt,
			KeyID:       "RSA_DECRYPT_OAEP_2048_SHA256",
		},
		{
			Name:  "RSA_DECRYPT_OAEP_2048_SHA256",
			KeyID: "RSA_DECRYPT_OAEP_2048_SHA256",
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()
			decrypter, err := NewDecrypter(ctx, tc.KeyID, clientOptions...)
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
				tc.DecrypterOpts,
			)

			if !errors.Is(err, tc.ResponseErr) {
				t.Fatalf("expected err=%s, got err=%s", tc.ResponseErr, err)
			}

			if tc.ResponseErr == nil {
				if string(plaintext) != testkeys.KnownInput {
					t.Errorf("expected plaintext=%s, got=%s", testkeys.KnownInput, plaintext)
				}
			}
		})
	}
}
