// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package ioutils_test

import (
	"path/filepath"
	"testing"

	"github.com/tprasadtp/cryptokms/internal/ioutils"
)

func Test_WriteBinaryBlob(t *testing.T) {
	type testCase struct {
		Name   string
		Blob   []byte
		Output string
		Err    bool
	}

	dir := t.TempDir()
	tt := []testCase{
		{
			Name:   "valid-blob",
			Output: filepath.Join(dir, "valid-blob"),
			Blob:   []byte("valid-blob-content"),
		},
		{
			Name:   "nil-blob",
			Output: filepath.Join(dir, "nil-blob"),
			Err:    true,
		},
		{
			Name:   "empty-blob",
			Output: filepath.Join(dir, "invalid-template"),
			Blob:   []byte{},
			Err:    true,
		},
		{
			Name:   "non-existent-output-path",
			Output: "/33ae370d-83d0-5819-bc18-8cd899168bb4/3e5c6c6f-49aa-5607-a239-5f985d7eaf66",
			Blob:   []byte("valid-blob-content"),
			Err:    true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			err := ioutils.WriteBlob(tc.Output, tc.Blob)
			if tc.Err {
				if err == nil {
					t.Errorf("expected to error, got nil")
				}
			} else {
				if err != nil {
					t.Error("unexpected error")
				}
			}
		})
	}
}
