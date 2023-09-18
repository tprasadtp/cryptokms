package testkeys_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

func TestMustMarshalPublicKey_Panics(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	shouldPanic(t, func() {
		testkeys.MustMarshalPublicKey(priv)
	})
}

func TestMustMarshalPublicKey_NotPanics(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	if testkeys.MustMarshalPublicKey(&key.PublicKey) == nil {
		t.Errorf("MustMarshalPublicKey must not return nil on valid key")
	}
}

func TestMustMarshalPrivateKey_Panics(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	shouldPanic(t, func() {
		testkeys.MustMarshalPrivateKey(priv.PublicKey)
	})
}

func TestMustMarshalPrivateKey_NotPanics(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	if testkeys.MustMarshalPrivateKey(key) == nil {
		t.Errorf("MustMarshalPrivateKey must not return nil on valid key")
	}
}
