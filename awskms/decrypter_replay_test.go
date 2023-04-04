package awskms_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/google/go-replayers/httpreplay"
	"github.com/tprasadtp/cryptokms/awskms"
	"github.com/tprasadtp/cryptokms/awskms/internal/testdata"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

func Test_Decrypter_Replay(t *testing.T) {
	type testCase struct {
		Name    string
		KeySpec string
	}
	tt := []testCase{
		{
			Name:    "encrypt-decrypt-rsa-4096",
			KeySpec: "RSA_4096",
		},
		{
			Name:    "encrypt-decrypt-rsa-3072",
			KeySpec: "RSA_3072",
		},
		{
			Name:    "encrypt-decrypt-rsa-2048",
			KeySpec: "RSA_2048",
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			// setup replayer
			rep, err := httpreplay.NewReplayer(fmt.Sprintf("internal/testdata/%s.replay.json", tc.Name))
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

			decrypter, err := awskms.NewDecrypter(ctx,
				client, testdata.MustGetKeyARN(tc.KeySpec, "ENCRYPT_DECRYPT"))
			if err != nil {
				t.Fatalf("failed to build decrypter")
			}

			// read encrypted file.
			encrypted, err := os.ReadFile(fmt.Sprintf("internal/testdata/%s.crypt", tc.Name))
			if err != nil {
				t.Fatalf("failed to read encrypted bytes: %s", err)
			}

			// decrypt using replayer
			plaintext, err := decrypter.DecryptContext(
				ctx, nil, encrypted, nil,
			)
			if err != nil {
				t.Fatalf("unexpected error on decrypt: %s", err)
			}

			if string(plaintext) != testkeys.KnownInput {
				t.Errorf("expected decrypted text to be=%s, but got=%s",
					testkeys.KnownInput, plaintext)
			}

			// ensure created at is not zero time
			if decrypter.CreatedAt().IsZero() {
				t.Errorf("CreatedAt() must not be zero")
			}
		})
	}
}
