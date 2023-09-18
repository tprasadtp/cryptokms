// Package fakekms implements crypto.Signer and crypto.Decrypter
// with ephemeral keys which are unique per execution of the binary.
//
//   - This package also provides a way to force returning errors on
//     sign/decrypt operation for use in integration or unit tests.
//   - This package should only be used in tests as keys are only
//     generated during init and are not rotated nor saved to any
//     persistent store.
package fakekms

import (
	"time"
)

// known TS.
var knownTS = time.Unix(1136239445, 0)
