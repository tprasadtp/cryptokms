// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package shared_test

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"testing"

	"github.com/tprasadtp/cryptokms/internal/shared"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

func shouldPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() { _ = recover() }()
	f()
	t.Errorf("%s => should panic, but did not", t.Name())
}

func TestMustMarshalPublicKey_Panics(t *testing.T) {
	shouldPanic(t, func() {
		shared.MustMarshalPublicKey(testkeys.GetRSA2048PrivateKey)
	})
}

func TestMustMarshalPublicKey_NotPanics(t *testing.T) {
	if shared.MustMarshalPublicKey(testkeys.GetRSA2048PrivateKey().Public()) == nil {
		t.Errorf("MustMarshalPublicKey must not return nil on valid key")
	}
}

func TestMustMarshalPrivateKey_Panics(t *testing.T) {
	shouldPanic(t, func() {
		shared.MustMarshalPrivateKey(testkeys.GetRSA2048PrivateKey().Public())
	})
}

func TestMustMarshalPrivateKey_NotPanics(t *testing.T) {
	if shared.MustMarshalPrivateKey(testkeys.GetRSA2048PrivateKey()) == nil {
		t.Errorf("MustMarshalPrivateKey must not return nil on valid key")
	}
}

func TestMustMarshalPKCS1PrivateKey_Panics(t *testing.T) {
	shouldPanic(t, func() {
		shared.MustMarshalPKCS1PrivateKey(&rsa.PrivateKey{})
	})
}

func TestMarshalPKCS1PrivateKey_NotPanics(t *testing.T) {
	if shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA2048PrivateKey()) == nil {
		t.Errorf("MustMarshalPrivateKey must not return nil on valid key")
	}
}

func TestMustMarshalECPrivateKey_Panics(t *testing.T) {
	shouldPanic(t, func() {
		shared.MustMarshalECPrivateKey(&ecdsa.PrivateKey{})
	})
}

func TestMustMarshalECPrivateKey_NotPanics(t *testing.T) {
	if shared.MustMarshalECPrivateKey(testkeys.GetECP256PrivateKey()) == nil {
		t.Errorf("MustMarshalECPrivateKey must not return nil on valid key")
	}
}
