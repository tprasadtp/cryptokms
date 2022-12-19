package cryptokms

import (
	_ "crypto/sha1" //nolint:gosec // SHA1 is used for encryption, not signing.
	_ "crypto/sha256"
	_ "crypto/sha512"
)
