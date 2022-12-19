package cryptoutils_test

import (
	"testing"

	"github.com/tprasadtp/cryptokms/internal/cryptoutils"
)

func Test_MustParseRSAPrivateKey(t *testing.T) {
	type testCase struct {
		Name   string
		Input  []byte
		Panics bool
	}
	tt := []testCase{
		{
			Name:   "nil-input",
			Input:  nil,
			Panics: true,
		},
		{
			Name:   "rsa-private-key-pkcs1",
			Input:  []byte(rsa2048PrivPKCS1),
			Panics: true,
		},
		{
			Name:   "rsa-public-key",
			Input:  []byte(rsa2048Pub),
			Panics: true,
		},
		{
			Name:   "ec-private-key-pkcs8",
			Input:  []byte(ecPrivPKCS8),
			Panics: true,
		},
		{
			Name:   "ec-private-key-notpkcs8",
			Input:  []byte(ecPrivNotPKCS8),
			Panics: true,
		},
		{
			Name:  "valid-rsa-pkcs8-private-key",
			Input: []byte(rsa2048PrivPKCS8),
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.Panics {
				shouldPanic(t, func() {
					cryptoutils.MustParseRSAPrivateKey(tc.Input)
				})
			} else {
				rv := cryptoutils.MustParseRSAPrivateKey(tc.Input)
				if rv == nil {
					t.Errorf("expected non nil output")
				}
			}
		})
	}
}

func Test_MustParseECPrivateKey(t *testing.T) {
	type testCase struct {
		Name   string
		Input  []byte
		Panics bool
	}
	tt := []testCase{
		{
			Name:   "nil-input",
			Input:  nil,
			Panics: true,
		},
		{
			Name:   "rsa-private-key-pkcs1",
			Input:  []byte(rsa2048PrivPKCS1),
			Panics: true,
		},
		{
			Name:   "rsa-public-key",
			Input:  []byte(rsa2048Pub),
			Panics: true,
		},
		{
			Name:   "rsa-private-key-pkcs8",
			Input:  []byte(rsa2048PrivPKCS8),
			Panics: true,
		},
		{
			Name:   "ec-private-key-notpkcs8",
			Input:  []byte(ecPrivNotPKCS8),
			Panics: true,
		},
		{
			Name:  "valid-ec-pkcs8-private-key",
			Input: []byte(ecPrivPKCS8),
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.Panics {
				shouldPanic(t, func() {
					cryptoutils.MustParseECPrivateKey(tc.Input)
				})
			} else {
				rv := cryptoutils.MustParseECPrivateKey(tc.Input)
				if rv == nil {
					t.Errorf("expected non nil output")
				}
			}
		})
	}
}
