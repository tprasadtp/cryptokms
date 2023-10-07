// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package ioutils

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// Given public key write to output file.
//   - If output file does not exist it is created.
//   - If output file exists, it is overwritten.
func WritePublicKey(output string, pub crypto.PublicKey) error {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("cryptokms(ioutils): failed to marshal public key: %w", err)
	}
	file, err := os.OpenFile(
		output,
		os.O_CREATE|os.O_TRUNC|os.O_WRONLY,
		0644,
	)
	if err != nil {
		return fmt.Errorf("cryptokms(ioutils): failed to open/create file %s : %w", output, err)
	}
	defer file.Close()

	// we truncated the file, so it is highly unlikely that write here fails.
	// thus it is not covered by unit tests.
	err = pem.Encode(file, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	})
	if err != nil {
		return fmt.Errorf("cryptokms(ioutils): failed to write publicKey to %s: %w", output, err)
	}
	return nil
}
