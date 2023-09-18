package filekms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
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

func TestNewDecrypter(t *testing.T) {
	type testCase struct {
		Name        string
		Path        string
		Response    *Decrypter
		ResponseErr error
		Valid       bool
	}
	dir := t.TempDir()
	tt := []testCase{
		{
			Name:        "rsa-1024",
			Path:        "internal/testdata/rsa-1024.pem",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name: "rsa-2048",
			Path: "internal/testdata/rsa-2048.pem",
			Response: &Decrypter{
				hash:             crypto.SHA256,
				maxCiphertextLen: 2048 / 8,
				algo:             cryptokms.AlgorithmRSA2048,
			},
			Valid: true,
		},
		{
			Name: "rsa-3072",
			Path: "internal/testdata/rsa-3072.pem",
			Response: &Decrypter{
				hash:             crypto.SHA256,
				maxCiphertextLen: 3072 / 8,
				algo:             cryptokms.AlgorithmRSA3072,
			},
			Valid: true,
		},
		{
			Name: "rsa-4096",
			Path: "internal/testdata/rsa-4096.pem",
			Response: &Decrypter{
				hash:             crypto.SHA256,
				maxCiphertextLen: 4096 / 8,
				algo:             cryptokms.AlgorithmRSA4096,
			},
			Valid: true,
		},
		{
			Name:        "ec-p256",
			Path:        "internal/testdata/ec-p256.pem",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "ec-p384",
			Path:        "internal/testdata/ec-p384.pem",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "ec-p521",
			Path:        "internal/testdata/ec-p521.pem",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "ed-25519",
			Path:        "internal/testdata/ed-25519.pem",
			ResponseErr: cryptokms.ErrKeyAlgorithm,
		},
		{
			Name:        "non-existing-file",
			Path:        filepath.Join(dir, "non-existing-file.pem"),
			ResponseErr: os.ErrNotExist,
		},
		{
			Name: "not-a-file",
			Path: dir,
		},
		{
			Name: "empty-file",
			Path: "internal/testdata/.gitkeep",
		},
		{
			Name: "public-key-file",
			Path: "../gcpkms/internal/testdata/rsa-sign-pkcs1-4096-sha512.pub",
		},
		{
			Name: "file-size-too-large",
			Path: func() string {
				file, err := os.CreateTemp(dir, "file-size-too-large-*.pem")
				if err != nil {
					t.Fatalf("failed to create temp file: %s", err)
				}
				defer file.Close()
				b := make([]byte, 9e3)
				h := make([]byte, hex.EncodedLen(9e3))
				_, err = rand.Read(b)
				if err != nil {
					t.Fatalf("failed to generate random bytes: %s", err)
				}
				hex.Encode(h, b)
				_, err = file.Write(h)
				if err != nil {
					t.Fatalf("failed to write random bytes: %s", err)
				}
				return file.Name()
			}(),
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			resp, err := NewDecrypter(tc.Path)
			diff := cmp.Diff(
				resp, tc.Response,
				cmp.AllowUnexported(Decrypter{}),
				cmpopts.IgnoreFields(Decrypter{}, "mu", "ts", "decrypter", "pub"))
			if diff != "" {
				t.Errorf("did not get expected response: \n%s", diff)
			}

			if !tc.Valid {
				if tc.ResponseErr != nil {
					if !errors.Is(err, tc.ResponseErr) {
						t.Errorf("expected error=%#v, but got=%#v", tc.ResponseErr, err)
					}
				} else {
					if err == nil {
						t.Errorf("expected non nil error")
					}
				}
			} else {
				if resp.Algorithm() != tc.Response.algo {
					t.Errorf("expected algo=%d, got=%d", tc.Response.algo, resp.Algorithm())
				}
				if resp.CreatedAt().IsZero() {
					t.Errorf("expected CreatedAt() to return non zero, got %s", resp.CreatedAt())
				}
				if resp.HashFunc() != tc.Response.hash {
					t.Errorf("expected HashFunc()=%s, got %s", tc.Response.hash, resp.HashFunc())
				}
				if v, _ := resp.DecrypterOpts().(*rsa.OAEPOptions); v.Hash != tc.Response.hash {
					t.Errorf("expected DecrypterOpts()=%#v, got %#v", tc.Response.hash, v)
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
		KeyFile       string
		DecrypterOpts any
	}
	tt := []testCase{
		{
			Name:    "rsa-2048-no-options",
			KeyFile: "internal/testdata/rsa-2048.pem",
			Encrypted: func() []byte {
				decrypter, _ := NewDecrypter("internal/testdata/rsa-2048.pem")
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
			KeyFile:       "internal/testdata/rsa-2048.pem",
			DecrypterOpts: &rsa.OAEPOptions{Hash: crypto.SHA1},
			Encrypted: func() []byte {
				decrypter, _ := NewDecrypter("internal/testdata/rsa-2048.pem")
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
			KeyFile:       "internal/testdata/rsa-2048.pem",
			DecrypterOpts: &rsa.OAEPOptions{Hash: crypto.SHA1, MGFHash: crypto.SHA256},
			Encrypted: func() []byte {
				decrypter, _ := NewDecrypter("internal/testdata/rsa-2048.pem")
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
			KeyFile:       "internal/testdata/rsa-2048.pem",
			DecrypterOpts: &rsa.OAEPOptions{Hash: crypto.SHA1, MGFHash: crypto.SHA1},
			Encrypted: func() []byte {
				buf := make([]byte, 8192)
				return buf
			}(),
			ResponseErr: cryptokms.ErrPayloadTooLarge,
		},
		{
			Name:          "rsa-2048-rsa-PKCS1v15DecryptOptions",
			KeyFile:       "internal/testdata/rsa-2048.pem",
			DecrypterOpts: &rsa.PKCS1v15DecryptOptions{},
			ResponseErr:   cryptokms.ErrDecrypterOpts,
		},
		{
			Name:          "rsa-2048-rsa-invalid-decrypter-option",
			KeyFile:       "internal/testdata/rsa-2048.pem",
			DecrypterOpts: crypto.SHA1,
			ResponseErr:   cryptokms.ErrDecrypterOpts,
		},
		{
			Name:          "rsa-2048-hash-mismatch",
			KeyFile:       "internal/testdata/rsa-2048.pem",
			DecrypterOpts: &rsa.OAEPOptions{Hash: crypto.SHA1},
			ResponseErr:   cryptokms.ErrAsymmetricDecrypt,
			Encrypted: func() []byte {
				decrypter, _ := NewDecrypter("internal/testdata/rsa-2048.pem")
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
			KeyFile:       "internal/testdata/rsa-4096.pem",
			DecrypterOpts: &rsa.OAEPOptions{Hash: crypto.SHA1},
			ResponseErr:   cryptokms.ErrAsymmetricDecrypt,
			Encrypted: func() []byte {
				decrypter, _ := NewDecrypter("internal/testdata/rsa-2048.pem")
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
			decrypter, err := NewDecrypter(tc.KeyFile)
			if err != nil {
				t.Fatalf("failed to build decrypter: %s", err)
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
