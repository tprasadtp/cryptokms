// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

// Package filekms implements [crypto.Signer] and [crypto.Decrypter]
// for keys stored on filesystem.
//
// Unless file is backed by ramfs or other in memory file-system
// this may be insecure. Keys MUST NOT be password protected.
package filekms
