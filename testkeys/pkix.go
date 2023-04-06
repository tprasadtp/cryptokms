package testkeys

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// MustMarshalPublicKey marshals public key to PEM format.
// It panics if [crypto/x509.MarshalPKIXPublicKey] returns an error.
func MustMarshalPublicKey(pub any) []byte {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal public Key: %s", err))
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	})
}
