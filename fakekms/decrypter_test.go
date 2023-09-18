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

func TestWithContext(t *testing.T) {
	s := new(Decrypter)
	ctx := context.Background()
	s = s.WithContext(ctx)

	if ctx != s.ctx {
		t.Fatalf("expected %#v to be %#v", ctx, s.ctx)
	}
}

func TestDecrypter_UnInitialized(t *testing.T) {
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

func TestNewDecrypter(t *testing.T) {
	type testCase struct {
		Name        string
		KeyID       string
		Response    *Decrypter
		ResponseErr error
	}
	tt := []testCase{
		{
			Name:  "rsa-2048",
			KeyID: "rsa-2048",
			Response: &Decrypter{
				decrypter:        testkeys.GetRSA2048PrivateKey(),
				pub:              testkeys.GetRSA2048PublicKey(),
				hash:             crypto.SHA256,
				rsa:              true,
				maxCiphertextLen: 2048 / 8,
				algo:             cryptokms.AlgorithmRSA2048,
			},
		},
		{
			Name:  "rsa-3072",
			KeyID: "rsa-3072",
			Response: &Decrypter{
				decrypter:        testkeys.GetRSA3072PrivateKey(),
				pub:              testkeys.GetRSA3072PublicKey(),
				hash:             crypto.SHA256,
				rsa:              true,
				maxCiphertextLen: 3072 / 8,
				algo:             cryptokms.AlgorithmRSA3072,
			},
		},
		{
			Name:  "rsa-4096",
			KeyID: "rsa-4096",
			Response: &Decrypter{
				decrypter:        testkeys.GetRSA4096PrivateKey(),
				pub:              testkeys.GetRSA4096PublicKey(),
				hash:             crypto.SHA256,
				rsa:              true,
				maxCiphertextLen: 4096 / 8,
				algo:             cryptokms.AlgorithmRSA4096,
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
				cmp.AllowUnexported(Decrypter{}),
				cmpopts.IgnoreFields(Decrypter{}, "mu"))
			if diff != "" {
				t.Errorf("did not get expected response: \n%s", diff)
			}

			if tc.ResponseErr == nil {
				if resp.Algorithm() != tc.Response.algo {
					t.Errorf("expected algo=%d, got=%d", tc.Response.algo, resp.Algorithm())
				}
				if !resp.CreatedAt().Equal(knownTS) {
					t.Errorf("expected CreatedAt() to return %s, got %s", knownTS, resp.CreatedAt())
				}
			}
		})
	}
}

func TestDecrypter_Decrypt(t *testing.T) {
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
			ResponseErr: cryptokms.ErrDecrypterOpts,
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
			Name:          "rsa-4096-key-mismatch",
			KeyID:         "rsa-4096",
			DecrypterOpts: &rsa.OAEPOptions{Hash: crypto.SHA1},
			ResponseErr:   cryptokms.ErrAsymmetricDecrypt,
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

func TestDecrypter_Decrypt_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	decrypter, _ := NewDecrypter("rsa-2048")
	_, err := decrypter.DecryptContext(ctx, rand.Reader, testkeys.KnownInputHash(crypto.SHA256), nil)
	if !errors.Is(err, cryptokms.ErrAsymmetricDecrypt) {
		t.Errorf("expected error(ErrAsymmetricDecrypt) when ctx is already cancelled")
	}
}
