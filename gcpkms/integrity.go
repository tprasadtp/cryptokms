package gcpkms

import (
	"hash/crc32"

	"google.golang.org/protobuf/types/known/wrapperspb"
)

// cache ctcTable for speed.
var crcTable = crc32.MakeTable(crc32.Castagnoli)

// Computes CRC32 checksum as recommended by [E2E in-transit integrity guidelines].
//
// [E2E in-transit integrity guidelines]: https://cloud.google.com/kms/docs/data-integrity-guidelines.
func ComputeCRC32(data []byte) *wrapperspb.Int64Value {
	// type conversion is safe here as wrapperspb.Int64Value is always
	// guaranteed to fit in unsigned 32 bit integer.
	return wrapperspb.Int64(int64(crc32.Checksum(data, crcTable)))
}
