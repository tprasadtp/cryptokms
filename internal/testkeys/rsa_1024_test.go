// This file is automatically generated. DO NOT EDIT.

package testkeys_test

import (
	"testing"

	"github.com/tprasadtp/cryptokms/internal/cryptoutils"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)


func Test_Get_RSA1024(t *testing.T) {
    // Ensure Public key is returned which corresponds to Private key
    priv := testkeys.GetRSA1024PrivateKey()
    if !priv.PublicKey.Equal(testkeys.GetRSA1024PublicKey()) {
        t.Errorf("GetRSA1024PrivateKey.PublicKey != GetRSA1024PrivateKey")
    }

    // Ensure GetRSA1024PublicKey returns same key as GetRSA1024PublicKeyPEM
    pubFromPEM := cryptoutils.MustParseRSAPublicKey(testkeys.GetRSA1024PublicKeyPEM())
	if !pubFromPEM.Equal(testkeys.GetRSA1024PublicKey()) {
		t.Errorf("parse(GetRSA1024PrivateKeyPEM) != GetRSA1024PrivateKey.Public")
	}
}
