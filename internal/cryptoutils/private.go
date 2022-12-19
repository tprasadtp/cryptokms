package cryptoutils

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// Just a wrapper around ParsePKCS8PrivateKey.
// Panics if key cannot be parsed.
func MustParsePrivateKey(key []byte) any {
	b, _ := pem.Decode(key)
	priv, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		panic(fmt.Sprintf("failed to parse ecdsa private key: %s", err))
	}
	return priv
}

// MustParseRSAPrivateKey Parse RSA Key from PEM.
// It panics if it cannot parse input key or key is of type other than *rsa.PrivateKey.
func MustParseRSAPrivateKey(key []byte) *rsa.PrivateKey {
	priv := MustParsePrivateKey(key)
	if rv, ok := priv.(*rsa.PrivateKey); !ok {
		panic(fmt.Sprintf("got %T, not *rsa.PrivateKey", priv))
	} else {
		return rv
	}
}

// MustParseECPrivateKey parses ECDSA Key from PEM.
// It panics if it cannot parse input key or key is of type other than *ecdsa.PrivateKey.
func MustParseECPrivateKey(key []byte) *ecdsa.PrivateKey {
	priv := MustParsePrivateKey(key)
	if rv, ok := priv.(*ecdsa.PrivateKey); !ok {
		panic(fmt.Sprintf("got %T, not *ecdsa.PrivateKey", priv))
	} else {
		return rv
	}
}
