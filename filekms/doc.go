// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

// Package filekms implements [crypto.Signer] and [crypto.Decrypter]
// for keys stored on locally mounted filesystem or memory.
//
// Unless file is backed by in memory file-system this may be insecure.
// Keys MUST NOT be password protected. Keys may be base64 encoded.
package filekms
