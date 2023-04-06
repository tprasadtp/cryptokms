package testkeys_test

import (
	"testing"

	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

func Test_MustParseRSAPublicKey_Panics(t *testing.T) {
	type testCase struct {
		Name string
		Func func()
	}
	tt := []testCase{
		{
			Name: "nil-input",
			Func: func() {
				testkeys.MustParseRSAPublicKey(nil)
			},
		},
		{
			Name: "rsa-private-key",
			Func: func() {
				testkeys.MustParseRSAPublicKey([]byte(rsa2048PrivPKCS8))
			},
		},
		{
			Name: "rsa-private-key-pkcs1",
			Func: func() {
				testkeys.MustParseRSAPublicKey([]byte(rsa2048PrivPKCS1))
			},
		},
		{
			Name: "ec-private-key-not-pkcs8",
			Func: func() {
				testkeys.MustParseRSAPublicKey([]byte(ecPrivNotPKCS8))
			},
		},
		{
			Name: "ec-private-key",
			Func: func() {
				testkeys.MustParseRSAPublicKey([]byte(ecPrivPKCS8))
			},
		},
		{
			Name: "ec-pub-key",
			Func: func() {
				testkeys.MustParseRSAPublicKey([]byte(ecPub))
			},
		},
		{
			Name: "ed25519-pub",
			Func: func() {
				testkeys.MustParseRSAPublicKey([]byte(ed25519Pub))
			},
		},
		{
			Name: "ed25519-priv",
			Func: func() {
				testkeys.MustParseRSAPublicKey([]byte(ed25519Priv))
			},
		},
		{
			Name: "invalid",
			Func: func() {
				testkeys.MustParseRSAPublicKey([]byte("foo bar"))
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			shouldPanic(t, tc.Func)
		})
	}
}

func Test_MustParseECPublicKey_Panics(t *testing.T) {
	type testCase struct {
		Name string
		Func func()
	}
	tt := []testCase{
		{
			Name: "nil-input",
			Func: func() {
				testkeys.MustParseECPublicKey(nil)
			},
		},
		{
			Name: "rsa-pub-key",
			Func: func() {
				testkeys.MustParseECPublicKey([]byte(rsa2048Pub))
			},
		},
		{
			Name: "rsa-private-key",
			Func: func() {
				testkeys.MustParseECPublicKey([]byte(rsa2048PrivPKCS8))
			},
		},
		{
			Name: "rsa-private-key-pkcs1",
			Func: func() {
				testkeys.MustParseECPublicKey([]byte(rsa2048PrivPKCS1))
			},
		},
		{
			Name: "ec-private-key-not-pkcs8",
			Func: func() {
				testkeys.MustParseECPublicKey([]byte(ecPrivNotPKCS8))
			},
		},
		{
			Name: "ec-private-key",
			Func: func() {
				testkeys.MustParseECPublicKey([]byte(ecPrivPKCS8))
			},
		},
		{
			Name: "ed25519-pub",
			Func: func() {
				testkeys.MustParseECPublicKey([]byte(ed25519Pub))
			},
		},
		{
			Name: "ed25519-priv",
			Func: func() {
				testkeys.MustParseECPublicKey([]byte(ed25519Priv))
			},
		},
		{
			Name: "invalid",
			Func: func() {
				testkeys.MustParseECPublicKey([]byte("foo bar"))
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			shouldPanic(t, tc.Func)
		})
	}
}

func Test_MustParsePublicKey_Valid(t *testing.T) {
	type testCase struct {
		Name string
		Func func() any
	}
	tt := []testCase{
		{
			Name: "valid-rsa-2048-public-key",
			Func: func() any {
				return testkeys.MustParseRSAPublicKey([]byte(rsa2048Pub))
			},
		},
		{
			Name: "valid-ec-public-key",
			Func: func() any {
				return testkeys.MustParseECPublicKey([]byte(ecPub))
			},
		},
		{
			Name: "valid-ed-25519-public-key",
			Func: func() any {
				return testkeys.MustParseED25519PublicKey([]byte(ed25519Pub))
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.Func() == nil {
				t.Errorf("expected non nil output")
			}
		})
	}
}
