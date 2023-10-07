// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package shared

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// ParsePrivateKey is a wrapper around
//
//   - [x509.ParsePKCS8PrivateKey]
//   - [x509.ParsePKCS1PrivateKey]
//   - [x509.ParseECPrivateKey].
//
// It can aso handle base64 encoded PEM keys.
func ParsePrivateKey[T string | []byte](key T) (crypto.PrivateKey, error) {
	kb := []byte(key)
	b64 := make([]byte, base64.RawStdEncoding.DecodedLen(len(kb)))
	if _, err := base64.StdEncoding.Decode(b64, kb); err == nil {
		kb = b64
	}

	// Check if data is PEM encoded.
	block, _ := pem.Decode(kb)
	if block == nil {
		return nil, fmt.Errorf("cryptokms/internal/parse: key is not PEM encoded")
	}

	// Try to parse it as PKCS8 ASN.1 DER format.
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)

	if err == nil {
		return priv, nil
	}

	// Try to parse it PKCS1 ASN.1 DER format.
	rsaPrivateKey, e1 := x509.ParsePKCS1PrivateKey(block.Bytes)
	if e1 == nil {
		return rsaPrivateKey, nil
	}

	// Try to parse it SEC1 ASN.1 DER format.
	ecPrivateKey, e2 := x509.ParseECPrivateKey(block.Bytes)
	if e2 == nil {
		return ecPrivateKey, nil
	}

	return nil, fmt.Errorf("cryptokms/internal/parse: key is invalid : %w", err)
}
