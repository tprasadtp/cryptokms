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

func TestSigner_UnInitialized(t *testing.T) {
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

func TestNewSigner(t *testing.T) {
	type testCase struct {
		Name        string
		KeyID       string
		Response    *Signer
		ResponseErr error
	}
	tt := []testCase{
		{
			Name:  "rsa-2048",
			KeyID: "rsa-2048",
			Response: &Signer{
				signer: testkeys.GetRSA2048PrivateKey(),
				pub:    testkeys.GetRSA2048PublicKey(),
				hash:   crypto.SHA256,
				rsa:    true,
				algo:   cryptokms.AlgorithmRSA2048,
			},
		},
		{
			Name:  "rsa-3072",
			KeyID: "rsa-3072",
			Response: &Signer{
				signer: testkeys.GetRSA3072PrivateKey(),
				pub:    testkeys.GetRSA3072PublicKey(),
				hash:   crypto.SHA256,
				rsa:    true,
				algo:   cryptokms.AlgorithmRSA3072,
			},
		},
		{
			Name:  "rsa-4096",
			KeyID: "rsa-4096",
			Response: &Signer{
				signer: testkeys.GetRSA4096PrivateKey(),
				pub:    testkeys.GetRSA4096PublicKey(),
				hash:   crypto.SHA256,
				rsa:    true,
				algo:   cryptokms.AlgorithmRSA4096,
			},
		},
		{
			Name:  "ec-p256",
			KeyID: "ec-p256",
			Response: &Signer{
				signer: testkeys.GetECP256PrivateKey(),
				pub:    testkeys.GetECP256PublicKey(),
				hash:   crypto.SHA256,
				algo:   cryptokms.AlgorithmECP256,
			},
		},
		{
			Name:  "ec-p384",
			KeyID: "ec-p384",
			Response: &Signer{
				signer: testkeys.GetECP384PrivateKey(),
				pub:    testkeys.GetECP384PublicKey(),
				hash:   crypto.SHA384,
				algo:   cryptokms.AlgorithmECP384,
			},
		},
		{
			Name:  "ec-p521",
			KeyID: "ec-p521",
			Response: &Signer{
				signer: testkeys.GetECP521PrivateKey(),
				pub:    testkeys.GetECP521PublicKey(),
				hash:   crypto.SHA512,
				algo:   cryptokms.AlgorithmECP521,
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
				cmp.AllowUnexported(Signer{}),
				cmpopts.IgnoreFields(Signer{}, "mu"))
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

func TestSigner_Sign(t *testing.T) {
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

func TestSigner_Sign_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	signer, _ := NewSigner("rsa-2048")
	_, err := signer.SignContext(ctx, rand.Reader, testkeys.KnownInputHash(crypto.SHA256), nil)
	if !errors.Is(err, cryptokms.ErrAsymmetricSign) {
		t.Errorf("expected error(ErrAsymmetricSign) when ctx is already cancelled")
	}
}
