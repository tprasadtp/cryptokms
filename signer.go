// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package cryptokms

import (
	"context"
	"crypto"
	"io"
	"time"
)

// Context aware KMS backed [crypto.Signer].
// This extends [crypto.Signer] with additional methods for usage with KMS keys.
type Signer interface {
	crypto.Signer

	// Same as [crypto.Signer], but [context.Context] aware.
	//  - KMS libraries are already context aware and should help with tracing,
	//    and cancellation.
	//  - Unlike [crypto.Signer], rand is always ignored, as signing may be remote.
	SignContext(ctx context.Context, rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)

	// KMS key creation time.
	//  - This can be used to calculate age of the key to help with periodic key rotation.
	//  - Building to GPG public key packets which are deterministic etc.
	CreatedAt() time.Time

	// Returns default hashing algorithm.
	//  - Some KMS providers restrict hashing algorithm. This
	//    ensures Signer selects appropriate hash supported by the KMS key.
	//  - If KMS key supports multiple signers, this
	//    returns sane default, typically [crypto.SHA256].
	HashFunc() crypto.Hash

	// Algorithm returns KMS key algorithm.
	Algorithm() Algorithm
}
