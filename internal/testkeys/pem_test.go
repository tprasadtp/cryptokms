package testkeys_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

func Test_MustMarshalPublicKey_Panics(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	shouldPanic(t, func() {
		testkeys.MustMarshalPublicKey(priv)
	})
}

func Test_MustMarshalPublicKey_NotPanics(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	if testkeys.MustMarshalPublicKey(&key.PublicKey) == nil {
		t.Errorf("MustMarshalPublicKey must not return nil on valid key")
	}
}
