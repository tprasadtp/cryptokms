// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package filekms

import (
	"crypto"
	"crypto/x509"
	"fmt"
)

// parsePrivateKey is a wrapper around [ParsePKCS8PrivateKey],
// [ParseECPrivateKey] and [ParsePKCS1PrivateKey].
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	// Try to parse it as PKCS8 ASN.1 DER format.
	priv, err := x509.ParsePKCS8PrivateKey(der)

	if err != nil {
		// Try to parse it PKCS1 ASN.1 DER format.
		rsaPrivKey, rsaErr := x509.ParsePKCS1PrivateKey(der)
		if rsaErr == nil {
			return rsaPrivKey, nil
		}

		// Try to parse it SEC1 ASN.1 DER format.
		ecPrivKey, ecErr := x509.ParseECPrivateKey(der)
		if ecErr == nil {
			return ecPrivKey, nil
		}
	}

	if v, ok := priv.(crypto.PrivateKey); ok {
		return v, nil
	}
	return nil, fmt.Errorf("unknown key type which does not implement crypto.PrivateKey")
}
