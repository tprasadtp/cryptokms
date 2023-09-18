// Package testkeys provides private RSA, ECC and ED-25519 keys
// to be used in unit and integration testing purposes.
// This will generate test keys upon import.
package testkeys

import (
	"crypto"
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

// MustMarshalPrivateKey marshals private key to PEM format.
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
