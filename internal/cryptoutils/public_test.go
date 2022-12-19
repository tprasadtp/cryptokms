package cryptoutils_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/tprasadtp/cryptokms/internal/cryptoutils"
)

func Test_MustParseRSAPublicKey(t *testing.T) {
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
			Name:   "rsa-private-key-pkcs8",
			Input:  []byte(rsa2048PrivPKCS8),
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
			Name:   "ec-public-key",
			Input:  []byte(ecPub),
			Panics: true,
		},
		{
			Name:  "valid-rsa-pkix-public-key",
			Input: []byte(rsa2048Pub),
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.Panics {
				shouldPanic(t, func() {
					cryptoutils.MustParseRSAPublicKey(tc.Input)
				})
			} else {
				rv := cryptoutils.MustParseRSAPublicKey(tc.Input)
				if rv == nil {
					t.Errorf("expected non nil output")
				}
			}
		})
	}
}

func Test_MustParseECPublicKey(t *testing.T) {
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
			Name:   "ec-private-key-pkcs8",
			Input:  []byte(ecPrivPKCS8),
			Panics: true,
		},
		{
			Name:  "valid-ec-pkcs8-public-key",
			Input: []byte(ecPub),
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.Panics {
				shouldPanic(t, func() {
					cryptoutils.MustParseECPublicKey(tc.Input)
				})
			} else {
				rv := cryptoutils.MustParseECPublicKey(tc.Input)
				if rv == nil {
					t.Errorf("expected non nil output")
				}
			}
		})
	}
}

func Test_MustMarshalECPublicKey_Panics(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	shouldPanic(t, func() {
		cryptoutils.MustMarshalPublicKey(key)
	})
}

func Test_MustMarshalECPublicKey_NotPanics(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	if cryptoutils.MustMarshalPublicKey(&key.PublicKey) == nil {
		t.Errorf("MustMarshalPublicKey must not return nil on valid key")
	}
}
