package fakekms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/tprasadtp/cryptokms"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

func Test_WithContext(t *testing.T) {
	s := new(SignerDecrypter)
	ctx := context.Background()
	s = s.WithContext(ctx)

	if ctx != s.ctx {
		t.Fatalf("expected %#v to be %#v", ctx, s.ctx)
	}
}

func Test_Sign_UnInitialized(t *testing.T) {
	signer := &SignerDecrypter{}
	_, err := signer.Sign(
		rand.Reader,
		testkeys.KnownInputHash(crypto.SHA256),
		crypto.SHA256,
	)

	if !errors.Is(err, cryptokms.ErrInvalidKMSClient) {
		t.Errorf("expected error=%+v, but got=%+v", cryptokms.ErrInvalidKMSClient, err)
	}
}

func Test_Decrypt_UnInitialized(t *testing.T) {
	decrypter := &SignerDecrypter{}
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

func Test_Signer_NewSigner(t *testing.T) {
	type testCase struct {
		Name        string
		KeyID       string
		Response    *SignerDecrypter
		ResponseErr error
	}
	tt := []testCase{
		{
			Name:  "rsa-2048",
			KeyID: "rsa-2048",
			Response: &SignerDecrypter{
				signer: testkeys.GetRSA2048PrivateKey(),
				pub:    testkeys.GetRSA2048PublicKey(),
				hash:   crypto.SHA256,
				rsa:    true,
			},
		},
		{
			Name:  "rsa-3072",
			KeyID: "rsa-3072",
			Response: &SignerDecrypter{
				signer: testkeys.GetRSA3072PrivateKey(),
				pub:    testkeys.GetRSA3072PublicKey(),
				hash:   crypto.SHA256,
				rsa:    true,
			},
		},
		{
			Name:  "rsa-4096",
			KeyID: "rsa-4096",
			Response: &SignerDecrypter{
				signer: testkeys.GetRSA4096PrivateKey(),
				pub:    testkeys.GetRSA4096PublicKey(),
				hash:   crypto.SHA256,
				rsa:    true,
			},
		},
		{
			Name:  "ec-p256",
			KeyID: "ec-p256",
			Response: &SignerDecrypter{
				signer: testkeys.GetECP256PrivateKey(),
				pub:    testkeys.GetECP256PublicKey(),
				hash:   crypto.SHA256,
			},
		},
		{
			Name:  "ec-p384",
			KeyID: "ec-p384",
			Response: &SignerDecrypter{
				signer: testkeys.GetECP384PrivateKey(),
				pub:    testkeys.GetECP384PublicKey(),
				hash:   crypto.SHA384,
			},
		},
		{
			Name:  "ec-p521",
			KeyID: "ec-p521",
			Response: &SignerDecrypter{
				signer: testkeys.GetECP521PrivateKey(),
				pub:    testkeys.GetECP521PublicKey(),
				hash:   crypto.SHA512,
			},
		},
		{
			Name:        "ec-secp256k1",
			KeyID:       "ec-secp256k1",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			resp, err := NewSigner(tc.KeyID)
			if !errors.Is(err, tc.ResponseErr) {
				t.Errorf("expected error=%+v, but got=%+v", tc.ResponseErr, err)
			}
			diff := cmp.Diff(
				resp, tc.Response,
				cmp.AllowUnexported(SignerDecrypter{}),
				cmpopts.IgnoreFields(SignerDecrypter{}, "mu"))
			if diff != "" {
				t.Errorf("did not get expected response: \n%s", diff)
			}

			if !resp.CreatedAt().Equal(knownTS) {
				t.Errorf("expected CreatedAt() to return %s, got %s", knownTS, resp.CreatedAt())
			}

			if resp.Backend() != cryptokms.BackendFakeKMS {
				t.Errorf("expected Backend=%v, got=%v", cryptokms.BackendFakeKMS, resp.Backend())
			}
		})
	}
}

func Test_Signer_Sign(t *testing.T) {
	type testCase struct {
		Name        string
		KeyID       string
		Digest      []byte
		Options     crypto.SignerOpts
		AlwaysErr   bool
		ResponseErr error
	}
	tt := []testCase{
		{
			Name:   "rsa-2048-no-options-sha256",
			KeyID:  "rsa-2048",
			Digest: testkeys.KnownInputHash(crypto.SHA256),
		},
		{
			Name:        "rsa-2048-no-options-sha1",
			KeyID:       "rsa-2048",
			Digest:      testkeys.KnownInputHash(crypto.SHA1),
			ResponseErr: cryptokms.ErrDigestLength,
		},
		{
			Name:    "rsa-2048-with-options-sha256",
			KeyID:   "rsa-2048",
			Digest:  testkeys.KnownInputHash(crypto.SHA256),
			Options: crypto.SHA256,
		},
		{
			Name:    "rsa-2048-with-pss-options-sha256",
			KeyID:   "rsa-2048",
			Digest:  testkeys.KnownInputHash(crypto.SHA256),
			Options: &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: crypto.SHA256.Size()},
		},
		{
			Name:    "rsa-2048-with-pss-options-missing-hash-func-sha256",
			KeyID:   "rsa-2048",
			Digest:  testkeys.KnownInputHash(crypto.SHA256),
			Options: &rsa.PSSOptions{SaltLength: crypto.SHA256.Size()},
		},
		{
			Name:        "rsa-2048-with-pss-options-mismatch-salt-and-hash-sha256",
			KeyID:       "rsa-2048",
			Digest:      testkeys.KnownInputHash(crypto.SHA256),
			Options:     &rsa.PSSOptions{SaltLength: crypto.SHA256.Size(), Hash: crypto.SHA512},
			ResponseErr: cryptokms.ErrSignerOpts,
		},
		{
			Name:        "rsa-2048-with-pss-options-mismatch-salt-and-hash-sha256",
			KeyID:       "rsa-2048",
			Digest:      testkeys.KnownInputHash(crypto.SHA256),
			Options:     &rsa.PSSOptions{SaltLength: crypto.SHA256.Size(), Hash: crypto.SHA512},
			ResponseErr: cryptokms.ErrSignerOpts,
		},
		{
			Name:        "ec-p256-with-pss-sha256",
			KeyID:       "ec-p256",
			Digest:      testkeys.KnownInputHash(crypto.SHA256),
			Options:     &rsa.PSSOptions{SaltLength: crypto.SHA256.Size(), Hash: crypto.SHA256},
			ResponseErr: cryptokms.ErrSignerOpts,
		},
		{
			Name:   "ec-p256-with-default",
			KeyID:  "ec-p256",
			Digest: testkeys.KnownInputHash(crypto.SHA256),
		},
		{
			Name:    "ec-p256-with-sha256",
			KeyID:   "ec-p256",
			Digest:  testkeys.KnownInputHash(crypto.SHA256),
			Options: crypto.SHA256,
		},
		{
			Name:        "ec-p256-with-sha256-invalid-hash",
			KeyID:       "ec-p256",
			Digest:      testkeys.KnownInputHash(crypto.SHA512),
			Options:     crypto.SHA256,
			ResponseErr: cryptokms.ErrDigestLength,
		},
		{
			Name:        "ec-p256-with-SHA512",
			KeyID:       "ec-p256",
			Digest:      testkeys.KnownInputHash(crypto.SHA256),
			Options:     crypto.SHA512,
			ResponseErr: cryptokms.ErrDigestLength,
		},
		{
			Name:        "ec-p256-always-err",
			KeyID:       "ec-p256",
			AlwaysErr:   true,
			Digest:      testkeys.KnownInputHash(crypto.SHA256),
			ResponseErr: cryptokms.ErrAsymmetricSign,
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()
			signer, err := NewSigner(tc.KeyID)
			if err != nil {
				t.Fatalf("failed to build signer - %s: %s", tc.KeyID, err)
			}

			if tc.AlwaysErr {
				signer = signer.WithAlwaysError()
			}

			signature, err := signer.WithContext(ctx).Sign(
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

func Test_Decrypter_NewDecrypter(t *testing.T) {
	type testCase struct {
		Name        string
		KeyID       string
		Response    *SignerDecrypter
		ResponseErr error
	}
	tt := []testCase{
		{
			Name:  "rsa-2048",
			KeyID: "rsa-2048",
			Response: &SignerDecrypter{
				decrypter:        testkeys.GetRSA2048PrivateKey(),
				pub:              testkeys.GetRSA2048PublicKey(),
				hash:             crypto.SHA256,
				rsa:              true,
				maxCiphertextLen: 2048 / 8,
			},
		},
		{
			Name:  "rsa-3072",
			KeyID: "rsa-3072",
			Response: &SignerDecrypter{
				decrypter:        testkeys.GetRSA3072PrivateKey(),
				pub:              testkeys.GetRSA3072PublicKey(),
				hash:             crypto.SHA256,
				rsa:              true,
				maxCiphertextLen: 3072 / 8,
			},
		},
		{
			Name:  "rsa-4096",
			KeyID: "rsa-4096",
			Response: &SignerDecrypter{
				decrypter:        testkeys.GetRSA4096PrivateKey(),
				pub:              testkeys.GetRSA4096PublicKey(),
				hash:             crypto.SHA256,
				rsa:              true,
				maxCiphertextLen: 4096 / 8,
			},
		},
		{
			Name:        "ec-p256",
			KeyID:       "ec-p256",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "ec-p384",
			KeyID:       "ec-p384",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "ec-p521",
			KeyID:       "ec-p521",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "ec-secp256k1",
			KeyID:       "ec-secp256k1",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			resp, err := NewDecrypter(tc.KeyID)
			if !errors.Is(err, tc.ResponseErr) {
				t.Errorf("expected error=%+v, but got=%+v", tc.ResponseErr, err)
			}
			diff := cmp.Diff(
				resp, tc.Response,
				cmp.AllowUnexported(SignerDecrypter{}),
				cmpopts.IgnoreFields(SignerDecrypter{}, "mu"))
			if diff != "" {
				t.Errorf("did not get expected response: \n%s", diff)
			}

			if resp.Backend() != cryptokms.BackendFakeKMS {
				t.Errorf("expected Backend=%v, got=%v", cryptokms.BackendFakeKMS, resp.Backend())
			}
		})
	}
}

func Test_Decrypter_Decrypt(t *testing.T) {
	type testCase struct {
		Name          string
		ResponseErr   error
		Encrypted     []byte
		KeyID         string
		DecrypterOpts any
		AlwaysErr     bool
	}
	tt := []testCase{
		{
			Name:  "rsa-2048-no-options",
			KeyID: "rsa-2048",
			Encrypted: func() []byte {
				decrypter, _ := NewDecrypter("rsa-2048")
				encrypted, err := rsa.EncryptOAEP(
					decrypter.HashFunc().New(),
					rand.Reader,
					decrypter.Public().(*rsa.PublicKey),
					[]byte(testkeys.KnownInput), nil,
				)
				if err != nil {
					t.Fatalf("failed to encrypt: %s", err)
				}
				return encrypted
			}(),
		},
		{
			Name:          "rsa-2048-rsa-oaep-sha1",
			KeyID:         "rsa-2048",
			DecrypterOpts: &rsa.OAEPOptions{Hash: crypto.SHA1},
			Encrypted: func() []byte {
				decrypter, _ := NewDecrypter("rsa-2048")
				encrypted, err := rsa.EncryptOAEP(
					crypto.SHA1.New(),
					rand.Reader,
					decrypter.Public().(*rsa.PublicKey),
					[]byte(testkeys.KnownInput), nil,
				)
				if err != nil {
					t.Fatalf("failed to encrypt: %s", err)
				}
				return encrypted
			}(),
		},
		{
			Name:          "rsa-2048-rsa-oaep-sha1-mismatch-mfghash",
			KeyID:         "rsa-2048",
			DecrypterOpts: &rsa.OAEPOptions{Hash: crypto.SHA1, MGFHash: crypto.SHA256},
			Encrypted: func() []byte {
				decrypter, _ := NewDecrypter("rsa-2048")
				encrypted, err := rsa.EncryptOAEP(
					crypto.SHA1.New(),
					rand.Reader,
					decrypter.Public().(*rsa.PublicKey),
					[]byte(testkeys.KnownInput), nil,
				)
				if err != nil {
					t.Fatalf("failed to encrypt: %s", err)
				}
				return encrypted
			}(),
			ResponseErr: cryptokms.ErrDigestAlgorithm,
		},
		{
			Name:          "rsa-2048-payload-too-large",
			KeyID:         "rsa-2048",
			DecrypterOpts: &rsa.OAEPOptions{Hash: crypto.SHA1, MGFHash: crypto.SHA1},
			Encrypted: func() []byte {
				buf := make([]byte, 8192)
				return buf
			}(),
			ResponseErr: cryptokms.ErrPayloadTooLarge,
		},
		{
			Name:          "rsa-2048-rsa-PKCS1v15DecryptOptions",
			KeyID:         "rsa-2048",
			DecrypterOpts: &rsa.PKCS1v15DecryptOptions{},
			ResponseErr:   cryptokms.ErrDecrypterOpts,
		},
		{
			Name:          "rsa-2048-rsa-invalid-decrypter-option",
			KeyID:         "rsa-2048",
			DecrypterOpts: crypto.SHA1,
			ResponseErr:   cryptokms.ErrDecrypterOpts,
		},
		{
			Name:        "rsa-2048-rsa-force-error",
			KeyID:       "rsa-2048",
			AlwaysErr:   true,
			ResponseErr: cryptokms.ErrAsymmetricDecrypt,
		},
		{
			Name:          "rsa-2048-hash-mismatch",
			KeyID:         "rsa-2048",
			DecrypterOpts: &rsa.OAEPOptions{Hash: crypto.SHA1},
			ResponseErr:   cryptokms.ErrAsymmetricDecrypt,
			Encrypted: func() []byte {
				decrypter, _ := NewDecrypter("rsa-2048")
				// should be SHA1
				encrypted, err := rsa.EncryptOAEP(
					crypto.SHA256.New(),
					rand.Reader,
					decrypter.Public().(*rsa.PublicKey),
					[]byte(testkeys.KnownInput), nil,
				)
				if err != nil {
					t.Fatalf("failed to encrypt: %s", err)
				}
				return encrypted
			}(),
		},
		{
			Name:          "rsa-2048-key-mismatch",
			KeyID:         "rsa-2048",
			DecrypterOpts: &rsa.OAEPOptions{Hash: crypto.SHA1},
			ResponseErr:   cryptokms.ErrAsymmetricDecrypt,
			Encrypted: func() []byte {
				decrypter, _ := NewDecrypter("rsa-4096")
				encrypted, err := rsa.EncryptOAEP(
					crypto.SHA1.New(),
					rand.Reader,
					decrypter.Public().(*rsa.PublicKey),
					[]byte(testkeys.KnownInput), nil,
				)
				if err != nil {
					t.Fatalf("failed to encrypt: %s", err)
				}
				return encrypted
			}(),
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			decrypter, err := NewDecrypter(tc.KeyID)
			if err != nil {
				t.Fatalf("failed to build decrypter: %s", err)
			}

			if tc.AlwaysErr {
				decrypter = decrypter.WithAlwaysError()
			}

			plaintext, err := decrypter.WithContext(context.Background()).Decrypt(
				rand.Reader,
				tc.Encrypted,
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
