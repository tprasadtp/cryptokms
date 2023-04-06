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
	// RSA2048 Private key.
	rsa2048PrivateKey *rsa.PrivateKey
	// RSA3072 Private key.
	rsa3072PrivateKey *rsa.PrivateKey
	// RSA4096 Private key.
	rsa4096PrivateKey *rsa.PrivateKey

	// ECDSA P-256  Private key.
	ecdsaP256PrivateKey *ecdsa.PrivateKey
	// ECDSA P-384  Private key.
	ecdsaP384PrivateKey *ecdsa.PrivateKey
	// ECDSA P-521  Private key.
	ecdsaP521PrivateKey *ecdsa.PrivateKey

	// ED-25519 PrivateKey.
	ed25519PrivateKey ed25519.PrivateKey
	// ED-25519 PublicKey.
	ed25519PublicKey ed25519.PublicKey
)

// Generate Keys.
//
//nolint:gochecknoinits // seed test keys
func init() {
	rsa2048PrivateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	rsa3072PrivateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	rsa4096PrivateKey, _ = rsa.GenerateKey(rand.Reader, 2048)

	ecdsaP256PrivateKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaP384PrivateKey, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ecdsaP521PrivateKey, _ = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	ed25519PublicKey, ed25519PrivateKey, _ = ed25519.GenerateKey(rand.Reader)
}

// Get2048PrivateKey returns a RSA 2048 bit private key.
// This private key is unique per execution of the binary and corresponds
// to public key returned by [GetRSA2048PublicKey].
func GetRSA2048PrivateKey() *rsa.PrivateKey {
	return rsa2048PrivateKey
}

// Get2048PublicKey returns a RSA 2048 bit public key.
// This pub key is unique per execution of the binary and corresponds
// to private key returned by [GetRSA2048PrivateKey].
func GetRSA2048PublicKey() *rsa.PublicKey {
	return &rsa2048PrivateKey.PublicKey
}

// Get3072PrivateKey returns a RSA 3072 bit private key.
// This private key is unique per execution of the binary and corresponds
// to public key returned by [GetRSA3072PublicKey].
func GetRSA3072PrivateKey() *rsa.PrivateKey {
	return rsa3072PrivateKey
}

// Get3072PublicKey returns a RSA 3072 bit public key.
// This pub key is unique per execution of the binary and corresponds
// to private key returned by [GetRSA3072PrivateKey].
func GetRSA3072PublicKey() *rsa.PublicKey {
	return &rsa3072PrivateKey.PublicKey
}

// Get4096PrivateKey returns a RSA 4096 bit private key.
// This private key is unique per execution of the binary and corresponds
// to public key returned by [GetRSA4096PublicKey].
func GetRSA4096PrivateKey() *rsa.PrivateKey {
	return rsa4096PrivateKey
}

// Get4096PublicKey returns a RSA 4096 bit public key.
// This pub key is unique per execution of the binary and corresponds
// to private key returned by [GetRSA4096PrivateKey].
func GetRSA4096PublicKey() *rsa.PublicKey {
	return &rsa4096PrivateKey.PublicKey
}

// GetEC256PrivateKey returns a EC P-256 bit private key.
// This private key is unique per execution of the binary and corresponds
// to public key returned by [GetGetEC256PublicKey].
func GetEC256PrivateKey() *ecdsa.PrivateKey {
	return ecdsaP256PrivateKey
}

// GetEC256PublicKey returns a EC P-256 bit public key.
// This pub key is unique per execution of the binary and corresponds
// to private key returned by [GetEC256PrivateKey].
func GetEC256PublicKey() *ecdsa.PublicKey {
	return &ecdsaP256PrivateKey.PublicKey
}

// GetEC384PrivateKey returns a EC P-384 bit private key.
// This private key is unique per execution of the binary and corresponds
// to public key returned by [GetGetEC384PublicKey].
func GetEC384PrivateKey() *ecdsa.PrivateKey {
	return ecdsaP384PrivateKey
}

// GetEC384PublicKey returns a EC P-384 bit public key.
// This pub key is unique per execution of the binary and corresponds
// to private key returned by [GetEC384PrivateKey].
func GetEC384PublicKey() *ecdsa.PublicKey {
	return &ecdsaP384PrivateKey.PublicKey
}

// GetEC521PrivateKey returns a EC P-521 bit private key.
// This private key is unique per execution of the binary and corresponds
// to public key returned by [GetGetEC521PublicKey].
func GetEC521PrivateKey() *ecdsa.PrivateKey {
	return ecdsaP521PrivateKey
}

// GetEC521PublicKey returns a EC P-521 bit public key.
// This pub key is unique per execution of the binary and corresponds
// to private key returned by [GetEC521PrivateKey].
func GetEC521PublicKey() *ecdsa.PublicKey {
	return &ecdsaP521PrivateKey.PublicKey
}

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
