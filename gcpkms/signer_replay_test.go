package gcpkms_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/google/go-replayers/grpcreplay"
	"github.com/tprasadtp/cryptokms"
	"github.com/tprasadtp/cryptokms/gcpkms"
	"github.com/tprasadtp/cryptokms/gcpkms/internal/testdata"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
	"google.golang.org/api/option"
)

func Test_Signer_GRPCReplay(t *testing.T) {
	type testCase struct {
		Name   string
		Digest []byte
	}
	tt := []testCase{
		{
			Name:   "ec-sign-p256-sha256",
			Digest: testkeys.KnownInputHash(crypto.SHA256),
		},
		{
			Name:   "ec-sign-p384-sha384",
			Digest: testkeys.KnownInputHash(crypto.SHA384),
		},
		{
			Name:   "rsa-sign-pkcs1-2048-sha256",
			Digest: testkeys.KnownInputHash(crypto.SHA256),
		},
		{
			Name:   "rsa-sign-pkcs1-3072-sha256",
			Digest: testkeys.KnownInputHash(crypto.SHA256),
		},
		{
			Name:   "rsa-sign-pkcs1-4096-sha256",
			Digest: testkeys.KnownInputHash(crypto.SHA256),
		},
		{
			Name:   "rsa-sign-pkcs1-4096-sha512",
			Digest: testkeys.KnownInputHash(crypto.SHA512),
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

			// setup signer
			signer, err := gcpkms.NewSigner(
				ctx,
				testdata.KeyVersionResourceName(tc.Name),
				option.WithGRPCConn(connection),
			)
			if err != nil {
				t.Fatalf("failed to setup signer: %s", err)
			}

			// sign using replayer
			signature, err := signer.SignContext(ctx, rand.Reader, tc.Digest, nil)
			if err != nil {
				t.Errorf("unexpected error on sign: %s", err)
			}

			err = cryptokms.VerifyDigestSignature(signer.Public(), signer.HashFunc(), tc.Digest, signature)
			if err != nil {
				t.Errorf("no signature not verified: %s", err)
			}

			// ensure created at is not zero time
			if signer.CreatedAt().IsZero() {
				t.Errorf("CreatedAt() must not be zero")
			}
		})
	}
}
