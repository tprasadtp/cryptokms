// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package cryptokms

import (
	"context"
	"crypto"
	"io"
	"time"
)

// Context aware KMS backed [crypto.Decrypter].
// This extends [crypto.Decrypter] with additional methods for usage with KMS keys.
type Decrypter interface {
	crypto.Decrypter

	// Same as [crypto.Decrypter], but [context.Context] aware.
	//  - KMS libraries are already context aware and should help with tracing, and cancellation.
	//  - Do note however decryption payload limits set by the kms provider apply.
	//  - Unlike [crypto.Decrypter], rand is ignored, as decryption may happen remotely.
	//    so it can be nil.
	DecryptContext(ctx context.Context, _ io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error)

	// KMS key creation time.
	//  - This can be used to calculate age of the key to help with periodic key rotation.
	//  - Building to GPG public key packets which are deterministic etc.
	CreatedAt() time.Time

	// Returns default hashing algorithm.
	//  - Some KMS providers restrict hashing algorithm.
	//  - If KMS key supports multiple algorithms, this
	//    returns sane default, typically [crypto.SHA256].
	HashFunc() crypto.Hash

	// Algorithm returns key algorithm.
	Algorithm() Algorithm
}
