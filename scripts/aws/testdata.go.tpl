// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

// This file is automatically generated. DO NOT EDIT.

// Package testdata includes fixtures, HTTP playback helpers
// and metadata for integration tests.
package testdata

import (
    "fmt"
    "strings"
)

// AWS Region used for generating test data.
const AWSRegion = "{{.Region}}"

// AWS KMS Endpoint Override.
const KMSEndpoint = "{{.KMSEndpoint}}"

// Key ARN is generated by server and is non-deterministic.
// Given keyType returns AWS ARN for that key. This relies on testdata.go
// as it ensures only one key of specified keySpec and key usage is generated.
// This function panics if no matching key is found.
//
// keyUsage can be
//  - SIGN_VERIFY for Singer keys
//  - ENCRYPT_DECRYPT fof Decrypter keys
//  - All other value results in panic.
//
// keySpec can be
//  - RSA_2048 (with key usage SIGN_VERIFY and ENCRYPT_DECRYPT)
//  - RSA_3072 (with key usage SIGN_VERIFY and ENCRYPT_DECRYPT)
//  - RSA_4096 (with key usage SIGN_VERIFY and ENCRYPT_DECRYPT)
//  - ECC_NIST_P256 (with key usage SIGN_VERIFY)
//  - ECC_NIST_P384 (with key usage SIGN_VERIFY)
//  - ECC_NIST_P512 (with key usage SIGN_VERIFY)
//  - any other value results in panic.
func MustGetKeyARN(keySpec, keyUsage string) string {
    switch strings.ToUpper(keyUsage) {
    case "ENCRYPT_DECRYPT":
        switch strings.ToUpper(keySpec) {
{{- range $index, $key := .Config.Keys -}}
{{- if eq $key.KeyUsage "ENCRYPT_DECRYPT"  }}
        case "{{$key.KeyAlgorithm}}":
            return "{{$key.KeyID}}"
{{- end }}
{{- end }}
        default:
            panic(fmt.Sprintf("unsupported keySpec=%s(%s)", keySpec, keyUsage))
        }
    case "SIGN_VERIFY":
        switch strings.ToUpper(keySpec) {
{{- range $index, $key := .Config.Keys -}}
{{- if eq $key.KeyUsage "SIGN_VERIFY"  }}
        case "{{$key.KeyAlgorithm}}":
            return "{{$key.KeyID}}"
{{- end }}
{{- end }}
        default:
            panic(fmt.Sprintf("unsupported keySpec=%s(%s)", keySpec, keyUsage))
        }
    default:
        panic(fmt.Sprintf("unsupported keyUsage=%s[%s]", keyUsage, keySpec))
    }
}
