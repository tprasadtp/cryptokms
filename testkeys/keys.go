package testkeys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
)

// Generate Keys on import once.
var (
	rsa2048PrivateKey *rsa.PrivateKey
	rsa3072PrivateKey *rsa.PrivateKey
	rsa4096PrivateKey *rsa.PrivateKey

	ecdsaP256PrivateKey *ecdsa.PrivateKey
	ecdsaP384PrivateKey *ecdsa.PrivateKey
	ecdsaP521PrivateKey *ecdsa.PrivateKey

	ed25519PrivateKey ed25519.PrivateKey
	ed25519PublicKey  ed25519.PublicKey
)

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

func GetRSA2048PrivateKey() *rsa.PrivateKey {
	return rsa2048PrivateKey
}

func GetRSA3072PrivateKey() *rsa.PrivateKey {
	return rsa3072PrivateKey
}

func GetRSA4096PrivateKey() *rsa.PrivateKey {
	return rsa4096PrivateKey
}

func GetRSA2048PublicKey() *rsa.PublicKey {
	return &rsa2048PrivateKey.PublicKey
}

func GetRSA2048PublicKeyPEM() []byte {
	return MustMarshalPublicKey(GetRSA2048PublicKey)
}

func GetRSA4096PublicKey() *rsa.PublicKey {
	return &rsa4096PrivateKey.PublicKey
}

func GetECP256PrivateKey() *ecdsa.PrivateKey {
	return ecdsaP256PrivateKey
}

func GetECP384PrivateKey() *ecdsa.PrivateKey {
	return ecdsaP384PrivateKey
}

func GetECP521PrivateKey() *ecdsa.PrivateKey {
	return ecdsaP521PrivateKey
}

func GetECP256PublicKey() *ecdsa.PublicKey {
	return &ecdsaP256PrivateKey.PublicKey
}

func GetECP384PublicKey() *ecdsa.PublicKey {
	return &ecdsaP384PrivateKey.PublicKey
}

func GetECP521PublicKey() *ecdsa.PublicKey {
	return &ecdsaP521PrivateKey.PublicKey
}

func GetED25519PrivateKey() ed25519.PrivateKey {
	return ed25519PrivateKey
}

func GetED25519PublicKey() ed25519.PublicKey {
	return ed25519PublicKey
}
