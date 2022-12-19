package testkeys_test

import (
	"crypto/ecdsa"
	"testing"

	"github.com/tprasadtp/cryptokms/internal/cryptoutils"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

func Test_Get_ECP256(t *testing.T) {
	// Ensure Key is of right type.
	priv := testkeys.GetECP256PrivateKey()
	if priv.Curve.Params().Name != "P-256" {
		t.Errorf("Invalid curve, expected=P-256, but got=%s", priv.Curve.Params().Name)
	}

	// Ensure Public key is returned which corresponds to Private key
	if !priv.PublicKey.Equal(testkeys.GetECP256PublicKey()) {
		t.Errorf("GetECP256PrivateKey/PublicKey != GetECP256PublicKey")
	}

	// Ensure GetECP256PublicKey returns same key as GetECP256PublicKeyPEM
	pubFromPEM := cryptoutils.MustParseECPublicKey(testkeys.GetECP256PublicKeyPEM())
	if !pubFromPEM.Equal(testkeys.GetECP256PublicKey()) {
		t.Errorf("parse(GetECP256PublicKeyPEM) != GetECP256PublicKey")
	}

	// Ensure GetECP256PublicKey returns same key as GetECP256PublicKeyPEM
	parsePEM := cryptoutils.MustParsePublicKey(testkeys.GetECP256PublicKeyPEM())
	if !parsePEM.(*ecdsa.PublicKey).Equal(testkeys.GetECP256PublicKey()) {
		t.Errorf("parse(GetECP256PublicKeyPEM) != GetECP256PublicKey")
	}
}
