// This file is automatically generated. DO NOT EDIT.

package testkeys

import (
	"crypto/ecdsa"

    _ "embed"
)

//go:embed keys/ecdsa_p521.key
var ecP521PrivateKeyPEM []byte

var ecP521PublicKeyPEM []byte
var ecP521PrivateKey *ecdsa.PrivateKey

//nolint:gochecknoinits // generated code
func init() {
    ecP521PrivateKey = MustParseECPrivateKey(ecP521PrivateKeyPEM)
    ecP521PublicKeyPEM = MustMarshalPublicKey(&ecP521PrivateKey.PublicKey)
}

// GetECP521PrivateKey returns a known ECDSA-P521 private key.
func GetECP521PrivateKey() *ecdsa.PrivateKey {
    return ecP521PrivateKey
}

// GetECP521PublicKey returns a known ECDSA-P521 public key.
func GetECP521PublicKey() *ecdsa.PublicKey {
    return &ecP521PrivateKey.PublicKey
}

// GetECP521PublicKeyPEM returns a known ECP521 private key in PEM format.
func GetECP521PublicKeyPEM() []byte {
    return ecP521PublicKeyPEM
}
