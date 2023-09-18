// This file is automatically generated. DO NOT EDIT.

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
{{ range $index, $bits :=  .RSA }}
    rsa{{ $bits }}PrivateKey *rsa.PrivateKey
{{- end }}
{{ range $index, $curve :=  .EC }}
	ecP{{ $curve }}PrivateKey *ecdsa.PrivateKey
{{- end }}

	ed25519PrivateKey ed25519.PrivateKey
	ed25519PublicKey ed25519.PublicKey
)

// Ensure keys are only generated if required.
var (
{{ range $index, $bits :=  .RSA }}
    rsa{{ $bits }}PrivateKeyOnce sync.Once
{{- end }}
{{ range $index, $curve :=  .EC }}
	ecP{{ $curve }}PrivateKeyOnce sync.Once
{{- end }}

	ed25519PrivateKeyOnce sync.Once
)

{{ range $index, $bits :=  .RSA }}
// Generate RSA-{{ $bits }} key.
func initOnceRSA{{ $bits }}() {
    rsa{{ $bits }}PrivateKey, _ = rsa.GenerateKey(rand.Reader, {{ $bits }})
}
{{- end }}

{{ range $index, $curve :=  .EC }}
// Generate EC-{{ $curve }} key.
func initOnceECP{{ $curve }}() {
	ecP{{ $curve }}PrivateKey, _ = ecdsa.GenerateKey(elliptic.P{{$curve}}(), rand.Reader)
}
{{- end }}

// Generate ED25519 key.
func initOnceEd25519Key() {
	ed25519PublicKey, ed25519PrivateKey, _ = ed25519.GenerateKey(rand.Reader)
}

{{ range $index, $bits :=  .RSA }}
// Get{{ $bits }}PrivateKey returns a RSA {{ $bits }} bit private key.
// This private key is unique per execution of the binary and corresponds
// to public key returned by [GetRSA{{ $bits }}PublicKey].
func GetRSA{{ $bits }}PrivateKey() *rsa.PrivateKey {
    rsa{{ $bits }}PrivateKeyOnce.Do(initOnceRSA{{ $bits }})
	return rsa{{ $bits }}PrivateKey
}

// Get{{ $bits }}PublicKey returns a RSA {{ $bits }} bit public key.
// This pub key is unique per execution of the binary and corresponds
// to private key returned by [GetRSA{{ $bits }}PrivateKey].
func GetRSA{{ $bits }}PublicKey() *rsa.PublicKey {
    rsa{{ $bits }}PrivateKeyOnce.Do(initOnceRSA{{ $bits }})
	return &rsa{{ $bits }}PrivateKey.PublicKey
}

// GetRSA{{ $bits }}PublicKey returns RSA {{ $bits }} bit public key in PEM format.
// This pub key is unique per execution of the binary and corresponds
// to private key returned by [GetRSA{{ $bits }}PrivateKey].
func GetRSA{{ $bits }}PublicKeyPEM() []byte {
    rsa{{ $bits }}PrivateKeyOnce.Do(initOnceRSA{{ $bits }})
	return MustMarshalPublicKey(&rsa{{ $bits }}PrivateKey.PublicKey)
}

{{ end }}

{{ range $index, $curve :=  .EC }}
// GetECP{{ $curve }}PrivateKey returns a EC P-{{ $curve }} bit private key.
// This private key is unique per execution of the binary and corresponds
// to public key returned by [GetECP{{ $curve }}PublicKey].
func GetECP{{ $curve }}PrivateKey() *ecdsa.PrivateKey {
    ecP{{ $curve }}PrivateKeyOnce.Do(initOnceECP{{ $curve }})
	return ecP{{ $curve }}PrivateKey
}

// GetECP{{ $curve }}PublicKey returns a EC P-{{ $curve }} bit public key.
// This pub key is unique per execution of the binary and corresponds
// to private key returned by [GetECP{{ $curve }}PrivateKey].
func GetECP{{ $curve }}PublicKey() *ecdsa.PublicKey {
    ecP{{ $curve }}PrivateKeyOnce.Do(initOnceECP{{ $curve }})
	return &ecP{{ $curve }}PrivateKey.PublicKey
}

// GetECP{{ $curve }}PublicKey returns EC P-{{ $curve }} public key in PEM format.
// This pub key is unique per execution of the binary and corresponds
// to private key returned by [GetECP{{ $curve }}PrivateKey].
func GetECP{{ $curve }}PublicKeyPEM() []byte {
    ecP{{ $curve }}PrivateKeyOnce.Do(initOnceECP{{ $curve }})
	return MustMarshalPublicKey(&ecP{{ $curve }}PrivateKey.PublicKey)
}

{{ end }}

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

// GetED25519PublicKeyPEM returns ED-25519 public key in PEM format.
func GetED25519PublicKeyPEM() []byte {
    ed25519PrivateKeyOnce.Do(initOnceEd25519Key)
	return MustMarshalPublicKey(ed25519PublicKey)
}

// GetED25519PrivateKeyPEM returns ED-25519 private key in PEM format.
func GetED25519PrivateKeyPEM() []byte {
    ed25519PrivateKeyOnce.Do(initOnceEd25519Key)
	return MustMarshalPrivateKey(ed25519PrivateKey)
}
