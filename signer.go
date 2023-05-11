package cryptokms

import (
	"context"
	"crypto"
	"io"
	"time"
)

// Context aware KMS backed [crypto.Signer].
// This extends [crypto.Signer] with additional methods for usage with KMS keys.
//
// This will be changed to use SignContext from Go Proposal [#56508], when its implemented.
//
// [#56508]: https://github.com/golang/go/issues/56508
type Signer interface {
	crypto.Signer

	// Same as [crypto.Signer], but [context.Context] aware.
	//  - KMS libraries are already context aware and should help with tracing,
	//    and cancellation.
	//  - Unlike [crypto.Signer], rand is ignored, as signing happens remotely.
	//  - It is recommended that you use HashFunc() for opts as it automatically
	//    selects the hash supported by the KMS key.
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

	// Some KMS providers restrict signing algorithm. This
	// enures Signer can return valid, supported [crypto.SignerOpts],
	// supported by the KMS key. If KMS key supports multiple decryption algorithms,
	// this returns sane default, typically RSA PKCS1v5 with SHA256.
	SignerOpts() crypto.SignerOpts

	// Returns KMS backend.
	Backend() Backend
}
