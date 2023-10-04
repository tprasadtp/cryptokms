// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

// This file is automatically generated. DO NOT EDIT.

// Package testdata includes fixtures, gRPC playback helpers
// and metadata for integration tests.
package testdata

import (
	"fmt"
)

// ProjectName is name of the GCP project used in recording gRPC responses.
// this is used in integration tests to build KMS key resource name.
const ProjectName = "crypto-kms-integration-testing"

// KeyringName is name of KMS keyring used in recording gRPC responses.
// this is used in integration tests to build KMS key resource name.
const KeyringName = "itest-b79b8dba"

// KeyringLocation is name of KMS keyring location used in recording gRPC responses.
// this is used in integration tests to build KMS key resource name.
const KeyringLocation = "global"

// KeyVersionResourceName Uses ProjectName, KeyringName, KeyringLocation
// and given key name to build qualified crypto key version GCP resource name.
//   - Only single version keys are supported.
//   - This must not to be used outside of testing gcpkms package.
func KeyVersionResourceName(name string) string {
	return fmt.Sprintf(
		"projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/1",
		ProjectName, KeyringLocation, KeyringName, name)
}
