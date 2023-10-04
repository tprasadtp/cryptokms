// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package testkeys_test

import (
	"testing"

	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

func Test_RSA_2048(t *testing.T) {
	// Ensure private key corresponds to public key
	if !testkeys.GetRSA2048PrivateKey().PublicKey.Equal(testkeys.GetRSA2048PublicKey()) {
		t.Error("key mismatch GetRSA2048PrivateKey != GetRSA2048PublicKey")
	}
}

func Test_RSA_3072(t *testing.T) {
	// Ensure private key corresponds to public key
	if !testkeys.GetRSA3072PrivateKey().PublicKey.Equal(testkeys.GetRSA3072PublicKey()) {
		t.Error("key mismatch GetRSA3072PrivateKey != GetRSA3072PublicKey")
	}
}

func Test_RSA_4096(t *testing.T) {
	// Ensure private key corresponds to public key
	if !testkeys.GetRSA4096PrivateKey().PublicKey.Equal(testkeys.GetRSA4096PublicKey()) {
		t.Error("key mismatch GetRSA4096PrivateKey != GetRSA4096PublicKey")
	}
}

func Test_EC_P256(t *testing.T) {
	// Ensure private key corresponds to public key
	if !testkeys.GetECP256PrivateKey().PublicKey.Equal(testkeys.GetECP256PublicKey()) {
		t.Error("key mismatch GetECP256PrivateKey != GetECP256PublicKey")
	}
}

func Test_EC_P384(t *testing.T) {
	// Ensure private key corresponds to public key
	if !testkeys.GetECP384PrivateKey().PublicKey.Equal(testkeys.GetECP384PublicKey()) {
		t.Error("key mismatch GetECP384PrivateKey != GetECP384PublicKey")
	}
}

func Test_EC_P521(t *testing.T) {
	// Ensure private key corresponds to public key
	if !testkeys.GetECP521PrivateKey().PublicKey.Equal(testkeys.GetECP521PublicKey()) {
		t.Error("key mismatch GetECP521PrivateKey != GetECP521PublicKey")
	}
}

func Test_ED25519(t *testing.T) {
	// Ensure private key corresponds to public key
	if !testkeys.GetED25519PublicKey().Equal(testkeys.GetED25519PrivateKey().Public()) {
		t.Error("key mismatch GetED25519PublicKey != GetED25519PrivateKey.Public()")
	}
}
