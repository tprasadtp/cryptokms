package gcpkms_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/google/go-replayers/grpcreplay"
	"github.com/tprasadtp/cryptokms/gcpkms"
	"github.com/tprasadtp/cryptokms/gcpkms/internal/testdata"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
	"google.golang.org/api/option"
)

func Test_Decrypter_GRPCReplay(t *testing.T) {
	type testCase struct {
		Name string
	}
	tt := []testCase{
		{
			Name: "rsa-decrypt-oaep-2048-sha1",
		},
		{
			Name: "rsa-decrypt-oaep-3072-sha1",
		},
		{
			Name: "rsa-decrypt-oaep-4096-sha1",
		},
		{
			Name: "rsa-decrypt-oaep-2048-sha256",
		},
		{
			Name: "rsa-decrypt-oaep-3072-sha256",
		},
		{
			Name: "rsa-decrypt-oaep-4096-sha256",
		},
		{
			Name: "rsa-decrypt-oaep-4096-sha512",
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			// setup replayer
			rep, err := grpcreplay.NewReplayer(
				fmt.Sprintf("internal/testdata/%s.replay", tc.Name), nil,
			)
			if err != nil {
				t.Fatalf("failed to setup replayer: %s", err)
			}
			defer rep.Close()
			connection, err := rep.Connection()
			if err != nil {
				t.Fatalf("failed to setup replayer connection: %s", err)
			}

			// setup client
			ctx := context.Background()
			client, err := kms.NewKeyManagementClient(ctx, option.WithGRPCConn(connection))
			if err != nil {
				t.Fatalf("failed to setup KMSClient: %s", err)
			}

			// setup decrypter
			decrypter, err := gcpkms.NewDecrypter(
				ctx,
				client,
				testdata.KeyVersionResourceName(tc.Name),
			)
			if err != nil {
				t.Fatalf("failed to setup decrypter: %s", err)
			}

			// read encrypted file.
			encrypted, err := os.ReadFile(fmt.Sprintf("internal/testdata/%s.crypt", tc.Name))
			if err != nil {
				t.Fatalf("failed to read encrypted bytes: %s", err)
			}

			// sign using replayer
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
