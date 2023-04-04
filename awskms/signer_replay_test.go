package awskms_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/google/go-replayers/httpreplay"
	"github.com/tprasadtp/cryptokms"
	"github.com/tprasadtp/cryptokms/awskms"
	"github.com/tprasadtp/cryptokms/awskms/internal/testdata"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

func Test_Signer_Replay(t *testing.T) {
	type testCase struct {
		Name    string
		KeySpec string
		Digest  []byte
	}
	tt := []testCase{
		{
			Name:    "sign-verify-rsa-4096",
			KeySpec: "RSA_4096",
			Digest:  testkeys.KnownInputHash(crypto.SHA256),
		},
		{
			Name:    "sign-verify-rsa-3072",
			KeySpec: "RSA_3072",
			Digest:  testkeys.KnownInputHash(crypto.SHA256),
		},
		{
			Name:    "sign-verify-rsa-2048",
			KeySpec: "RSA_2048",
			Digest:  testkeys.KnownInputHash(crypto.SHA256),
		},
		{
			Name:    "sign-verify-ecc-nist-p521",
			KeySpec: "ECC_NIST_P521",
			Digest:  testkeys.KnownInputHash(crypto.SHA512),
		},
		{
			Name:    "sign-verify-ecc-nist-p384",
			KeySpec: "ECC_NIST_P384",
			Digest:  testkeys.KnownInputHash(crypto.SHA384),
		},
		{
			Name:    "sign-verify-ecc-nist-p256",
			KeySpec: "ECC_NIST_P256",
			Digest:  testkeys.KnownInputHash(crypto.SHA256),
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			// setup replayer
			rep, err := httpreplay.NewReplayer(
				fmt.Sprintf("internal/testdata/%s.replay.json", tc.Name))
			if err != nil {
				t.Fatalf("failed to setup replayer: %s", err)
			}
			defer rep.Close()

			// setup client
			ctx := context.Background()
			client := kms.New(kms.Options{
				Region:           testdata.AWSRegion,
				HTTPClient:       rep.Client(),
				Credentials:      &aws.AnonymousCredentials{},
				EndpointResolver: &endpointResolver{},
			})

			signer, err := awskms.NewSigner(ctx, client,
				testdata.MustGetKeyARN(tc.KeySpec, "SIGN_VERIFY"))
			if err != nil {
				t.Fatalf("failed to build signer")
			}

			// sign using replayer
			signature, err := signer.SignContext(ctx, rand.Reader, tc.Digest, nil)
			if err != nil {
				t.Errorf("unexpected error on sign: %s", err)
			}

			err = cryptokms.VerifyDigestSignature(signer.Public(), signer.HashFunc(), tc.Digest, signature)
			if err != nil {
				t.Errorf("signature not verified: %s", err)
			}

			// ensure created at is not zero time
			if signer.CreatedAt().IsZero() {
				t.Errorf("CreatedAt() must not be zero")
			}
		})
	}
}
