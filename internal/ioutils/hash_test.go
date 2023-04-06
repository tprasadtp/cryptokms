package ioutils_test

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/tprasadtp/cryptokms/internal/ioutils"
)

const knownInput = "Oh Be A Fine Girl Kiss Me"

//nolint:exhaustive // no need to test all hashes.
var knownInputHash = map[crypto.Hash]string{
	crypto.SHA1:   "66e0f3de54a965818f911317feaa79ae618f3ce9",
	crypto.SHA256: "381d492615cee4337ef441d9fb2e3682c0306fb99b82ff966af4cc5dc8db61b7",
	crypto.SHA384: "8d2dc2415f84bcd1e2cbcdc8328f7b53f1be1886ab4f04ceac2ad5248f92aba705547cf736be91551b69af129892533b",
	crypto.SHA512: "e97f080062f244ff1f51e6225cbb91978554a19ffd5a53e8d46ed010496b0a92da9ad64bde8bb3147e6f6f3d204262edea72e2267ee07456f57a1a74eb22f718",
}

// uselessReader implements [io.Reader] which always errors.
type uselessReader struct{}

// Always return [io.ErrUnexpectedEOF] on Read.
func (uselessReader) Read(p []byte) (int, error) {
	return 0, fmt.Errorf("%w: useless reader always returns error", io.ErrUnexpectedEOF)
}

func Test_HashBlob(t *testing.T) {
	type testCase struct {
		Name         string
		Hash         crypto.Hash
		Input        io.Reader
		ExpectedHash string
		Err          error
	}
	tt := []testCase{
		{
			Name:         "sha-256",
			Input:        bytes.NewBufferString(knownInput),
			Hash:         crypto.SHA256,
			ExpectedHash: knownInputHash[crypto.SHA256],
		},
		{
			Name:         "sha-384",
			Input:        bytes.NewBufferString(knownInput),
			Hash:         crypto.SHA384,
			ExpectedHash: knownInputHash[crypto.SHA384],
		},
		{
			Name:         "sha-512",
			Input:        bytes.NewBufferString(knownInput),
			Hash:         crypto.SHA512,
			ExpectedHash: knownInputHash[crypto.SHA512],
		},
		{
			Name:  "reader-error",
			Input: &uselessReader{},
			Hash:  crypto.SHA512,
			Err:   io.ErrUnexpectedEOF,
		},
		{
			Name:  "hash-not-available",
			Input: bytes.NewBufferString(knownInput),
			Hash:  crypto.Hash(0),
			Err:   ioutils.ErrDigestAlgorithmUnavailable,
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			digest, err := ioutils.HashBlob(tc.Input, tc.Hash)

			if !errors.Is(err, tc.Err) {
				t.Fatalf("Expected error=%s, got=%s", tc.Err, err)
			}

			if tc.Err == nil {
				if h := hex.EncodeToString(digest); h != tc.ExpectedHash {
					t.Errorf("expected hash=%s, got=%s", tc.ExpectedHash, h)
				}
			}
		})
	}
}
