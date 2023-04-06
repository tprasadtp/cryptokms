// Package testkeys provides private RSA, ECC and ED-25519 keys
// to be used in unit and integration testing purposes.
// This will generate test keys upon import.
// So every test run will use a different key.
// If your system runs out of entropy, tests might fail.
// If using a VM, please ensure to attach viorng device to
// prevent entropy exhaustion.
package testkeys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
)

// Keys are generated on package import
// These keys must only be used for testing.
var (
{{- range $index, $bits :=  .RSA }}
    // RSA{{ $bits }} Private key.
	rsa{{ $bits }}PrivateKey *rsa.PrivateKey
{{- end }}
{{ range $index, $curve :=  .EC }}
    // ECDSA P-{{ $curve }}  Private key.
	ecdsaP{{ $curve }}PrivateKey *ecdsa.PrivateKey
{{- end }}

    // ED-25519 PrivateKey.
	ed25519PrivateKey ed25519.PrivateKey
    // ED-25519 PublicKey.
	ed25519PublicKey ed25519.PublicKey
)

// Generate Keys.
//
//nolint:gochecknoinits // seed test keys
func init() {
{{- range $index, $bits :=  .RSA }}
	rsa{{ $bits }}PrivateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
{{- end }}
{{ range $index, $curve :=  .EC }}
	ecdsaP{{ $curve }}PrivateKey, _ = ecdsa.GenerateKey(elliptic.P{{$curve}}(), rand.Reader)
{{- end }}
	ed25519PublicKey, ed25519PrivateKey, _ = ed25519.GenerateKey(rand.Reader)
}
{{- range $index, $bits :=  .RSA }}

// Get{{ $bits }}PrivateKey returns a RSA {{ $bits }} bit private key.
// This private key is unique per execution of the binary and corresponds
// to public key returned by [GetRSA{{ $bits }}PublicKey].
func GetRSA{{ $bits }}PrivateKey() *rsa.PrivateKey {
	return rsa{{ $bits }}PrivateKey
}

// Get{{ $bits }}PublicKey returns a RSA {{ $bits }} bit public key.
// This pub key is unique per execution of the binary and corresponds
// to private key returned by [GetRSA{{ $bits }}PrivateKey].
func GetRSA{{ $bits }}PublicKey() *rsa.PublicKey {
	return &rsa{{ $bits }}PrivateKey.PublicKey
}
{{- end }}
{{- range $index, $curve :=  .EC }}

// GetEC{{ $curve }}PrivateKey returns a EC P-{{ $curve }} bit private key.
// This private key is unique per execution of the binary and corresponds
// to public key returned by [GetGetEC{{ $curve }}PublicKey].
func GetEC{{ $curve }}PrivateKey() *ecdsa.PrivateKey {
	return ecdsaP{{ $curve }}PrivateKey
}

// GetEC{{ $curve }}PublicKey returns a EC P-{{ $curve }} bit public key.
// This pub key is unique per execution of the binary and corresponds
// to private key returned by [GetEC{{ $curve }}PrivateKey].
func GetEC{{ $curve }}PublicKey() *ecdsa.PublicKey {
	return &ecdsaP{{ $curve }}PrivateKey.PublicKey
}
{{- end }}

// GetED25519PrivateKey returns ED-25519 private key.
// This private key is unique per execution of the binary
// and corresponds to public key returned by [GetED25519PublicKey].
func GetED25519PrivateKey() ed25519.PrivateKey {
	return ed25519PrivateKey
}

// GetED25519PublicKey returns ED-25519 public key.
// This public key is unique per execution of the binary
// and corresponds to private key returned by [GetED25519PrivateKey].
func GetED25519PublicKey() ed25519.PublicKey {
	return ed25519PublicKey
}
