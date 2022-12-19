// This file is automatically generated. DO NOT EDIT.

package testkeys

import (
	"crypto/rsa"
    _ "embed"

    "github.com/tprasadtp/cryptokms/internal/cryptoutils"
)

//go:embed keys/rsa_2048.key
var rsa2048PrivateKeyPEM []byte

var rsa2048PublicKeyPEM []byte
var rsa2048PrivateKey *rsa.PrivateKey

//nolint:gochecknoinits // generated code
func init() {
    rsa2048PrivateKey = cryptoutils.MustParseRSAPrivateKey(rsa2048PrivateKeyPEM)
	rsa2048PublicKeyPEM = cryptoutils.MustMarshalPublicKey(&rsa2048PrivateKey.PublicKey)
}

// GetRSA2048PrivateKey returns a known RSA2048 private key.
func GetRSA2048PrivateKey() *rsa.PrivateKey {
    return rsa2048PrivateKey
}

// GetRSA2048PublicKey returns a known RSA2048 private key.
func GetRSA2048PublicKey() *rsa.PublicKey {
    return &rsa2048PrivateKey.PublicKey
}

// GetRSA2048PublicKeyPEM returns a known RSA2048 public key in PEM format.
func GetRSA2048PublicKeyPEM() []byte {
    return rsa2048PublicKeyPEM
}
