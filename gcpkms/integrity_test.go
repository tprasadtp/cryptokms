// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package gcpkms

import (
	"testing"

	"google.golang.org/protobuf/types/known/wrapperspb"
)

func Test_ComputeCRC32(t *testing.T) {
	type testCase struct {
		Name   string
		Input  []byte
		Expect *wrapperspb.Int64Value
	}

	tt := []testCase{
		{
			Name:   "empty-data",
			Expect: wrapperspb.Int64(0),
		},
		{
			Name:   "sha256-hash-value",
			Input:  []byte("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			Expect: wrapperspb.Int64(3437706977),
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			got := computeCRC32(tc.Input)
			if got.Value != tc.Expect.Value {
				t.Errorf("expected '%d(%x)', but got '%d(%x)'",
					tc.Expect.Value,
					tc.Expect.Value,
					got.Value,
					got.Value,
				)
			}
		})
	}
}
