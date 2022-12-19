package testkeys_test

import (
	"crypto"
	"encoding/hex"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

func Test_KnownDigest(t *testing.T) {
	type testCase struct {
		Name           string
		Hash           crypto.Hash
		ExpectedDigest string
	}
	tt := []testCase{
		{
			Name:           "sha1",
			Hash:           crypto.SHA1,
			ExpectedDigest: "66e0f3de54a965818f911317feaa79ae618f3ce9",
		},
		{
			Name:           "sha256",
			Hash:           crypto.SHA256,
			ExpectedDigest: "381d492615cee4337ef441d9fb2e3682c0306fb99b82ff966af4cc5dc8db61b7",
		},
		{
			Name:           "sha384",
			Hash:           crypto.SHA384,
			ExpectedDigest: "8d2dc2415f84bcd1e2cbcdc8328f7b53f1be1886ab4f04ceac2ad5248f92aba705547cf736be91551b69af129892533b",
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			digest := testkeys.KnownInputHash(tc.Hash)
			expected, _ := hex.DecodeString(tc.ExpectedDigest)
			if diff := cmp.Diff(digest, expected); diff != "" {
				t.Errorf("unexpected hash diff: %s", diff)
			}
		})
	}
}
