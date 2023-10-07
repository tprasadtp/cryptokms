// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package shared

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// MustMarshalPublicKey marshals public key to PEM format.
// It panics if [crypto/x509.MarshalPKIXPublicKey] returns an error.
func MustMarshalPublicKey(pub crypto.PublicKey) []byte {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal public Key: %s", err))
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	})
}

// MustMarshalPrivateKey marshals private key to PKCS8 PEM format.
// It panics if [crypto/x509.MarshalPKCS8PrivateKey] returns an error.
func MustMarshalPrivateKey(priv crypto.PrivateKey) []byte {
	b, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal private Key: %s", err))
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	})
}

// MustMarshalPKCS1PrivateKey marshals RSA private key to PKCS1 PEM format.
// It panics if key is nil.
func MustMarshalPKCS1PrivateKey(priv *rsa.PrivateKey) []byte {
	if priv == nil {
		panic("MustMarshalPKCS1PrivateKey: key cannot be nil")
	}
	b := x509.MarshalPKCS1PrivateKey(priv)
	pem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: b,
	})
	return pem
}

// MustMarshalPKCS1PrivateKey marshals RSA private key to PKCS1 PEM format.
// It panics if key is nil.
func MustMarshalECPrivateKey(priv *ecdsa.PrivateKey) []byte {
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		panic(fmt.Sprintf("PEMEncodeECDSA: %s", err))
	}
	pem := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: b,
	})
	return pem
}
