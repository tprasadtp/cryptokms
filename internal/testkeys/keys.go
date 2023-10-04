// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package testkeys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"sync"
)

// Keys are generated on package import
// These keys must only be used for testing.
var (
	rsa1024PrivateKey *rsa.PrivateKey
	rsa2048PrivateKey *rsa.PrivateKey
	rsa3072PrivateKey *rsa.PrivateKey
	rsa4096PrivateKey *rsa.PrivateKey

	ecP224PrivateKey *ecdsa.PrivateKey
	ecP256PrivateKey *ecdsa.PrivateKey
	ecP384PrivateKey *ecdsa.PrivateKey
	ecP521PrivateKey *ecdsa.PrivateKey

	ed25519PrivateKey ed25519.PrivateKey
	ed25519PublicKey  ed25519.PublicKey
)

// Ensure keys are only generated if required.
var (
	rsa1024PrivateKeyOnce sync.Once
	rsa2048PrivateKeyOnce sync.Once
	rsa3072PrivateKeyOnce sync.Once
	rsa4096PrivateKeyOnce sync.Once

	ecP224PrivateKeyOnce sync.Once
	ecP256PrivateKeyOnce sync.Once
	ecP384PrivateKeyOnce sync.Once
	ecP521PrivateKeyOnce sync.Once

	ed25519PrivateKeyOnce sync.Once
)

// Generate RSA-1024 key.
func initOnceRSA1024() {
	//nolint:gosec // testkeys used for testing
	rsa1024PrivateKey, _ = rsa.GenerateKey(rand.Reader, 1024)
}

// Generate RSA-2048 key.
func initOnceRSA2048() {
	rsa2048PrivateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
}

// Generate RSA-3072 key.
func initOnceRSA3072() {
	rsa3072PrivateKey, _ = rsa.GenerateKey(rand.Reader, 3072)
}

// Generate RSA-4096 key.
func initOnceRSA4096() {
	rsa4096PrivateKey, _ = rsa.GenerateKey(rand.Reader, 4096)
}

// Generate EC-P224 key.
func initOnceECP224() {
	ecP224PrivateKey, _ = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
}

// Generate EC-P256 key.
func initOnceECP256() {
	ecP256PrivateKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// Generate EC-P384 key.
func initOnceECP384() {
	ecP384PrivateKey, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

// Generate EC-P521 key.
func initOnceECP521() {
	ecP521PrivateKey, _ = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
}

// Generate ED25519 key.
func initOnceEd25519Key() {
	ed25519PublicKey, ed25519PrivateKey, _ = ed25519.GenerateKey(rand.Reader)
}

// Get1024PrivateKey returns a RSA 1024 bit private key.
// This private key is unique per execution of the binary and corresponds
// to public key returned by [GetRSA1024PublicKey].
func GetRSA1024PrivateKey() *rsa.PrivateKey {
	rsa1024PrivateKeyOnce.Do(initOnceRSA1024)
	return rsa1024PrivateKey
}

// Get2048PrivateKey returns a RSA 2048 bit private key.
// This private key is unique per execution of the binary and corresponds
// to public key returned by [GetRSA2048PublicKey].
func GetRSA2048PrivateKey() *rsa.PrivateKey {
	rsa2048PrivateKeyOnce.Do(initOnceRSA2048)
	return rsa2048PrivateKey
}

// Get1024PublicKey returns a RSA 1024 bit public key.
// This pub key is unique per execution of the binary and corresponds
// to private key returned by [GetRSA1024PrivateKey].
func GetRSA1024PublicKey() *rsa.PublicKey {
	rsa1024PrivateKeyOnce.Do(initOnceRSA1024)
	return &rsa1024PrivateKey.PublicKey
}

// Get2048PublicKey returns a RSA 2048 bit public key.
// This pub key is unique per execution of the binary and corresponds
// to private key returned by [GetRSA2048PrivateKey].
func GetRSA2048PublicKey() *rsa.PublicKey {
	rsa2048PrivateKeyOnce.Do(initOnceRSA2048)
	return &rsa2048PrivateKey.PublicKey
}

// Get3072PrivateKey returns a RSA 3072 bit private key.
// This private key is unique per execution of the binary and corresponds
// to public key returned by [GetRSA3072PublicKey].
func GetRSA3072PrivateKey() *rsa.PrivateKey {
	rsa3072PrivateKeyOnce.Do(initOnceRSA3072)
	return rsa3072PrivateKey
}

// Get3072PublicKey returns a RSA 3072 bit public key.
// This pub key is unique per execution of the binary and corresponds
// to private key returned by [GetRSA3072PrivateKey].
func GetRSA3072PublicKey() *rsa.PublicKey {
	rsa3072PrivateKeyOnce.Do(initOnceRSA3072)
	return &rsa3072PrivateKey.PublicKey
}

// Get4096PrivateKey returns a RSA 4096 bit private key.
// This private key is unique per execution of the binary and corresponds
// to public key returned by [GetRSA4096PublicKey].
func GetRSA4096PrivateKey() *rsa.PrivateKey {
	rsa4096PrivateKeyOnce.Do(initOnceRSA4096)
	return rsa4096PrivateKey
}

// Get4096PublicKey returns a RSA 4096 bit public key.
// This pub key is unique per execution of the binary and corresponds
// to private key returned by [GetRSA4096PrivateKey].
func GetRSA4096PublicKey() *rsa.PublicKey {
	rsa4096PrivateKeyOnce.Do(initOnceRSA4096)
	return &rsa4096PrivateKey.PublicKey
}

// GetECP224PrivateKey returns a EC P-224 bit private key.
// This private key is unique per execution of the binary and corresponds
// to public key returned by [GetECP224PublicKey].
func GetECP224PrivateKey() *ecdsa.PrivateKey {
	ecP224PrivateKeyOnce.Do(initOnceECP224)
	return ecP224PrivateKey
}

// GetECP224PublicKey returns a EC P-224 bit public key.
// This pub key is unique per execution of the binary and corresponds
// to private key returned by [GetECP224PrivateKey].
func GetECP224PublicKey() *ecdsa.PublicKey {
	ecP224PrivateKeyOnce.Do(initOnceECP224)
	return &ecP224PrivateKey.PublicKey
}

// GetECP256PrivateKey returns a EC P-256 bit private key.
// This private key is unique per execution of the binary and corresponds
// to public key returned by [GetECP256PublicKey].
func GetECP256PrivateKey() *ecdsa.PrivateKey {
	ecP256PrivateKeyOnce.Do(initOnceECP256)
	return ecP256PrivateKey
}

// GetECP256PublicKey returns a EC P-256 bit public key.
// This pub key is unique per execution of the binary and corresponds
// to private key returned by [GetECP256PrivateKey].
func GetECP256PublicKey() *ecdsa.PublicKey {
	ecP256PrivateKeyOnce.Do(initOnceECP256)
	return &ecP256PrivateKey.PublicKey
}

// GetECP384PrivateKey returns a EC P-384 bit private key.
// This private key is unique per execution of the binary and corresponds
// to public key returned by [GetECP384PublicKey].
func GetECP384PrivateKey() *ecdsa.PrivateKey {
	ecP384PrivateKeyOnce.Do(initOnceECP384)
	return ecP384PrivateKey
}

// GetECP384PublicKey returns a EC P-384 bit public key.
// This pub key is unique per execution of the binary and corresponds
// to private key returned by [GetECP384PrivateKey].
func GetECP384PublicKey() *ecdsa.PublicKey {
	ecP384PrivateKeyOnce.Do(initOnceECP384)
	return &ecP384PrivateKey.PublicKey
}

// GetECP521PrivateKey returns a EC P-521 bit private key.
// This private key is unique per execution of the binary and corresponds
// to public key returned by [GetECP521PublicKey].
func GetECP521PrivateKey() *ecdsa.PrivateKey {
	ecP521PrivateKeyOnce.Do(initOnceECP521)
	return ecP521PrivateKey
}

// GetECP521PublicKey returns a EC P-521 bit public key.
// This pub key is unique per execution of the binary and corresponds
// to private key returned by [GetECP521PrivateKey].
func GetECP521PublicKey() *ecdsa.PublicKey {
	ecP521PrivateKeyOnce.Do(initOnceECP521)
	return &ecP521PrivateKey.PublicKey
}

// GetED25519PrivateKey returns ED-25519 private key.
// This private key is unique per execution of the binary
// and corresponds to public key returned by [GetED25519PublicKey].
func GetED25519PrivateKey() ed25519.PrivateKey {
	ed25519PrivateKeyOnce.Do(initOnceEd25519Key)
	return ed25519PrivateKey
}

// GetED25519PublicKey returns ED-25519 public key.
// This public key is unique per execution of the binary
// and corresponds to private key returned by [GetED25519PrivateKey].
func GetED25519PublicKey() ed25519.PublicKey {
	ed25519PrivateKeyOnce.Do(initOnceEd25519Key)
	return ed25519PublicKey
}
