package cryptoutils

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// Just a wrapper around ParsePKIXPublicKey.
// Panics if key cannot be parsed.
func MustParsePublicKey(key []byte) any {
	b, _ := pem.Decode(key)
	pub, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		panic(fmt.Sprintf("failed to parse ecdsa public key: %s", err))
	}
	return pub
}

// MustParseRSAPublicKey parses RSA public key in PEM format.
// It panics if it cannot parse input key or key is of type other than *rsa.PublicKey.
func MustParseRSAPublicKey(key []byte) *rsa.PublicKey {
	pub := MustParsePublicKey(key)
	if rv, ok := pub.(*rsa.PublicKey); !ok {
		panic(fmt.Sprintf("got %T, not *rsa.PublicKey", pub))
	} else {
		return rv
	}
}

// MustParseECPublicKey parses EC public key in PEM format.
// It panics if it cannot parse input key or key is of type other than *ecdsa.PublicKey.
func MustParseECPublicKey(key []byte) *ecdsa.PublicKey {
	pub := MustParsePublicKey(key)
	if rv, ok := pub.(*ecdsa.PublicKey); !ok {
		panic(fmt.Sprintf("got %T, not *ecdsa.PublicKey", pub))
	} else {
		return rv
	}
}

// MustMarshalPublicKey marshals public key to PEM format.
// It panics if [x509.MarshalPKIXPublicKey] returns an error.
func MustMarshalPublicKey(pub any) []byte {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal Public Key: %s", err))
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	})
}
