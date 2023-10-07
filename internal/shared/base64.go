// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package shared

import "encoding/base64"

// EncodeBase64 encodes given pem string or bytes to base64 bytes.
func EncodeBase64[T string | []byte](pem T) []byte {
	rv := make([]byte, base64.StdEncoding.EncodedLen(len(pem)))
	base64.StdEncoding.Encode(rv, []byte(pem))
	return rv
}
