// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package shared_test

import (
	"testing"

	"github.com/tprasadtp/cryptokms/internal/shared"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

func TestPrivateKey(t *testing.T) {
	type testCase struct {
		name  string
		input []byte
		ok    bool
	}
	tt := []testCase{
		{
			name: "nil",
		},
		{
			name:  "rsa-2048-pem-pkcs1",
			input: shared.MustMarshalPrivateKey(testkeys.GetRSA2048PrivateKey()),
			ok:    true,
		},
		{
			name:  "rsa-2048-base64-pem-pkcs1",
			input: shared.EncodeBase64(shared.MustMarshalPKCS1PrivateKey(testkeys.GetRSA2048PrivateKey())),
			ok:    true,
		},
		{
			name:  "rsa-2048-pem-pkcs8",
			input: shared.MustMarshalPrivateKey(testkeys.GetRSA2048PrivateKey()),
			ok:    true,
		},
		{
			name:  "rsa-2048-base64-pem-pkcs8",
			input: shared.EncodeBase64(shared.MustMarshalPrivateKey(testkeys.GetRSA2048PrivateKey())),
			ok:    true,
		},
		// ECDSA
		{
			name:  "ecdsa-p256",
			input: shared.MustMarshalECPrivateKey(testkeys.GetECP256PrivateKey()),
			ok:    true,
		},
		{
			name:  "ecdsa-p256-base64",
			input: shared.EncodeBase64(shared.MustMarshalECPrivateKey(testkeys.GetECP256PrivateKey())),
			ok:    true,
		},
		{
			name:  "ecdsa-p256-pkcs8",
			input: shared.MustMarshalPrivateKey(testkeys.GetECP256PrivateKey()),
			ok:    true,
		},
		{
			name:  "ecdsa-p256-pkcs8-base64",
			input: shared.EncodeBase64(shared.MustMarshalPrivateKey(testkeys.GetECP256PrivateKey())),
			ok:    true,
		},
		// Ed25519
		{
			name:  "ed25519-pkcs8",
			input: shared.MustMarshalPrivateKey(testkeys.GetED25519PrivateKey()),
			ok:    true,
		},
		{
			name:  "ed25519-base64",
			input: shared.EncodeBase64(shared.MustMarshalPrivateKey(testkeys.GetED25519PrivateKey())),
			ok:    true,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := shared.ParsePrivateKey(tc.input)
			if tc.ok {
				if err != nil {
					t.Errorf("expected no error, got: %s", err)
				}
				if priv == nil {
					t.Errorf("expected non nil private key")
				}
			} else {
				if err == nil {
					t.Errorf("expected error, got nil")
				}

				if priv != nil {
					t.Errorf("expected nil priv key when parse returns an error")
				}
			}
		})
	}
}
