package ioutils_test

import (
	"path/filepath"
	"testing"

	"github.com/tprasadtp/cryptokms/internal/ioutils"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

func Test_WritePublicKey(t *testing.T) {
	type testCase struct {
		Name   string
		Output string
		Pub    any
		Err    bool
	}
	dir := t.TempDir()
	tt := []testCase{
		{
			Name:   "valid-rsa-public-key",
			Pub:    testkeys.GetRSA2048PublicKey(),
			Output: filepath.Join(dir, "valid-rsa-public-key.pub"),
		},
		{
			Name:   "valid-ec-public-key",
			Pub:    testkeys.GetECP256PublicKey(),
			Output: filepath.Join(dir, "valid-ec-public-key.pub"),
		},
		{
			Name:   "invalid-output-path",
			Pub:    testkeys.GetECP256PublicKey(),
			Output: "/33ae370d-83d0-5819-bc18-8cd899168bb4/3e5c6c6f-49aa-5607-a239-5f985d7eaf66",
			Err:    true,
		},
		{
			Name:   "invalid-private-key",
			Pub:    testkeys.GetECP256PrivateKey(),
			Output: filepath.Join(dir, "invalid-private-key.pub"),
			Err:    true,
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			err := ioutils.WritePublicKey(tc.Output, tc.Pub)
			if tc.Err {
				if err == nil {
					t.Error("expected to error, but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %s", err)
				}
			}
		})
	}
}

func Test_WritePrivateKey(t *testing.T) {
	type testCase struct {
		Name   string
		Output string
		Priv   any
		Err    bool
	}
	dir := t.TempDir()
	tt := []testCase{
		{
			Name:   "valid-rsa-public-key",
			Priv:   testkeys.GetRSA2048PrivateKey(),
			Output: filepath.Join(dir, "valid-rsa-public-key.pub"),
		},
		{
			Name:   "valid-ec-public-key",
			Priv:   testkeys.GetECP256PrivateKey(),
			Output: filepath.Join(dir, "valid-ec-public-key.pub"),
		},
		{
			Name:   "invalid-output-path",
			Priv:   testkeys.GetECP256PrivateKey(),
			Output: "/33ae370d-83d0-5819-bc18-8cd899168bb4/3e5c6c6f-49aa-5607-a239-5f985d7eaf66",
			Err:    true,
		},
		{
			Name:   "invalid-public-key",
			Priv:   testkeys.GetECP256PublicKey(),
			Output: filepath.Join(dir, "invalid-private-key.pub"),
			Err:    true,
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			err := ioutils.WritePrivateKey(tc.Output, tc.Priv)
			if tc.Err {
				if err == nil {
					t.Error("expected to error, but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %s", err)
				}
			}
		})
	}
}
