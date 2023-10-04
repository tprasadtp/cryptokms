// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package cryptokms

// Key algorithm type.
//
//go:generate go run golang.org/x/tools/cmd/stringer@latest -type Algorithm -trimprefix=Algorithm
type Algorithm int

const (
	// Unknown.
	AlgorithmUnknown Algorithm = iota

	// RSA 2048 bit key.
	AlgorithmRSA2048

	// RSA 3072 bit key.
	AlgorithmRSA3072

	// RSA 4096 bit key.
	AlgorithmRSA4096

	// RSA 8192 bit key.
	AlgorithmRSA8192

	// NIST P-256 elliptic curve key algorithms.
	AlgorithmECP256

	// NIST P-384 elliptic curve key algorithms.
	AlgorithmECP384

	// NIST P-521 elliptic curve key algorithms.
	AlgorithmECP521

	// ED-25519.
	AlgorithmED25519

	// AWS symmetric key algorithm.
	AlgorithmSymmetricAWS

	// GCP symmetric key algorithm.
	AlgorithmSymmetricGCP
)
