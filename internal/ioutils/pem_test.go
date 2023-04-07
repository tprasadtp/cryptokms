package ioutils_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"path/filepath"
	"testing"

	"github.com/tprasadtp/cryptokms/internal/ioutils"
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
			Name: "valid-rsa-public-key",
			Pub: func() *rsa.PublicKey {
				priv, _ := rsa.GenerateKey(rand.Reader, 2048)
				return &priv.PublicKey
			}(),
			Output: filepath.Join(dir, "valid-rsa-public-key.pub"),
		},
		{
			Name: "valid-ec-public-key",
			Pub: func() *ecdsa.PublicKey {
				priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return &priv.PublicKey
			}(),
			Output: filepath.Join(dir, "valid-ec-public-key.pub"),
		},
		{
			Name: "invalid-output-path",
			Pub: func() *ecdsa.PublicKey {
				priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return &priv.PublicKey
			}(),
			Output: "/33ae370d-83d0-5819-bc18-8cd899168bb4/3e5c6c6f-49aa-5607-a239-5f985d7eaf66",
			Err:    true,
		},
		{
			Name: "invalid-private-key",
			Pub: func() *ecdsa.PrivateKey {
				priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return priv
			}(),
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
