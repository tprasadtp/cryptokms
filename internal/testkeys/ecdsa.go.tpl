// This file is automatically generated. DO NOT EDIT.

package testkeys

import (
	"crypto/ecdsa"

    _ "embed"
)

//go:embed keys/ecdsa_p{{.Size}}.key
var ecP{{.Size}}PrivateKeyPEM []byte

var ecP{{.Size}}PublicKeyPEM []byte
var ecP{{.Size}}PrivateKey *ecdsa.PrivateKey

//nolint:gochecknoinits // generated code
func init() {
    ecP{{.Size}}PrivateKey = MustParseECPrivateKey(ecP{{.Size}}PrivateKeyPEM)
    ecP{{.Size}}PublicKeyPEM = MustMarshalPublicKey(&ecP{{.Size}}PrivateKey.PublicKey)
}

// GetECP{{.Size}}PrivateKey returns a known ECDSA-P{{.Size}} private key.
func GetECP{{.Size}}PrivateKey() *ecdsa.PrivateKey {
    return ecP{{.Size}}PrivateKey
}

// GetECP{{.Size}}PublicKey returns a known ECDSA-P{{.Size}} public key.
func GetECP{{.Size}}PublicKey() *ecdsa.PublicKey {
    return &ecP{{.Size}}PrivateKey.PublicKey
}

// GetECP{{.Size}}PublicKeyPEM returns a known ECP{{.Size}} private key in PEM format.
func GetECP{{.Size}}PublicKeyPEM() []byte {
    return ecP{{.Size}}PublicKeyPEM
}
