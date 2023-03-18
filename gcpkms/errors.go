package gcpkms

import "github.com/tprasadtp/cryptokms"

const (
	// ErrResponseIntegrity is returned if response is corrupt and
	// does not match expected CRC32 checksum.
	ErrResponseIntegrity = cryptokms.Error("gcpkms: response corrupted in transit")
	// ErrRequestIntegrity is returned when server recognizes that request data
	// is corrupt and does not match expected CRC32 checksum.
	ErrRequestIntegrity = cryptokms.Error("gcpkms: request corrupted in transit")
)
