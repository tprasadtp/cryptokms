// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package testkeys

import (
	"crypto"
)

// KnownInput is wellknown digest input.
// A nod to [Stellar classification].
//
// [Stellar classification]: https://en.wikipedia.org/wiki/Stellar_classification
const KnownInput = "Oh Be A Fine Girl Kiss Me"

// KnownInputHash Hashes [KnownInput] with specified hash algorithm.
func KnownInputHash(hash crypto.Hash) []byte {
	h := hash.New()
	h.Write([]byte(KnownInput))
	return h.Sum(nil)
}
