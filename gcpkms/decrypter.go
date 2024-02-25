// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package gcpkms

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"sync"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/tprasadtp/cryptokms"
	"google.golang.org/api/option"
)

var (
	_ crypto.Decrypter    = (*Decrypter)(nil)
	_ cryptokms.Decrypter = (*Decrypter)(nil)
)

// Decrypter is backed by a supported Google cloud KMS asymmetric key.
// Only following key types are supported.
//   - RSA_DECRYPT_OAEP_2048_SHA1
//   - RSA_DECRYPT_OAEP_3072_SHA1
//   - RSA_DECRYPT_OAEP_4096_SHA1
//   - RSA_DECRYPT_OAEP_2048_SHA256
//   - RSA_DECRYPT_OAEP_3072_SHA256
//   - RSA_DECRYPT_OAEP_4096_SHA256
//   - RSA_DECRYPT_OAEP_4096_SHA512
//
// At minimum, following IAM permissions are required.
//   - cloudkms.cryptoKeyVersions.get
//   - cloudkms.cryptoKeyVersions.useToDecrypt
//   - cloudkms.cryptoKeyVersions.viewPublicKey
//   - cloudkms.locations.get
//   - cloudkms.locations.list
//   - resourcemanager.projects.get
//
// Alternatively assign following roles. But it includes
// more permissions than absolutely required.
//   - [cloudkms.cryptoOperator]
//   - [cloudkms.viewer]
//
// [cloudkms.viewer]: https://cloud.google.com/kms/docs/reference/permissions-and-roles#cloudkms.viewer
// [cloudkms.cryptoOperator]: https://cloud.google.com/kms/docs/reference/permissions-and-roles#cloudkms.cryptoOperator
//
//nolint:containedctx // ignore
type Decrypter struct {
	name   string
	ctx    context.Context
	mu     sync.RWMutex
	pub    crypto.PublicKey
	hash   crypto.Hash
	ctime  time.Time
	algo   cryptokms.Algorithm
	client *kms.KeyManagementClient
}

// Returns a new Decrypter backed by GCP KMS asymmetric key.
func NewDecrypter(ctx context.Context, keyID string, opts ...option.ClientOption) (*Decrypter, error) {
	client, err := kms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("gcpkms: failed to build kms client: %w", err)
	}

	// Get key metadata.
	key, err := client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{Name: keyID})
	if err != nil {
		return nil, fmt.Errorf("gcpkms: failed to get key version: %w", err)
	}

	if key.State != kmspb.CryptoKeyVersion_ENABLED {
		return nil, fmt.Errorf("gcpkms: key(%s) is in unusable sate - %s", keyID, key.State)
	}

	// Check key compatibility and hash algorithm.
	var hasher crypto.Hash
	var algo cryptokms.Algorithm

	switch key.Algorithm {
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA1:
		hasher = crypto.SHA1
		algo = cryptokms.AlgorithmRSA2048
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA1:
		hasher = crypto.SHA1
		algo = cryptokms.AlgorithmRSA3072
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA1:
		hasher = crypto.SHA1
		algo = cryptokms.AlgorithmRSA4096
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256:
		hasher = crypto.SHA256
		algo = cryptokms.AlgorithmRSA2048
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256:
		hasher = crypto.SHA256
		algo = cryptokms.AlgorithmRSA3072
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256:
		hasher = crypto.SHA256
		algo = cryptokms.AlgorithmRSA4096
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA512:
		hasher = crypto.SHA512
		algo = cryptokms.AlgorithmRSA4096
	// Unsupported Methods
	case kmspb.CryptoKeyVersion_HMAC_SHA1,
		kmspb.CryptoKeyVersion_HMAC_SHA224,
		kmspb.CryptoKeyVersion_HMAC_SHA256,
		kmspb.CryptoKeyVersion_HMAC_SHA384,
		kmspb.CryptoKeyVersion_HMAC_SHA512:
		return nil, fmt.Errorf("gcpkms: hmac key(%s) cannot be used for decryption", keyID)
	case kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION:
		return nil, fmt.Errorf("gcpkms: symmetric key(%s) are not supported for decryption", keyID)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512,
		kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		return nil, fmt.Errorf("gcpkms: signing key(%s) cannot be used for decryption", keyID)
	default:
		return nil, fmt.Errorf("gcpkms: unknown or unsupported key algorithm - %s", key.Algorithm)
	}

	// Retrieve the public key from KMS.
	pbPublicKey, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: keyID})
	if err != nil {
		return nil, fmt.Errorf("gcpkms: failed to get public key: %w", err)
	}

	// Verify response integrity.
	crcHash := computeCRC32([]byte(pbPublicKey.Pem))
	if crcHash.Value != pbPublicKey.PemCrc32C.Value {
		return nil, fmt.Errorf("gcpkms: public key data integrity is invalid, expected CRC32=%x got=%x",
			pbPublicKey.PemCrc32C, crcHash.Value)
	}

	// Parse public key PEM
	block, _ := pem.Decode([]byte(pbPublicKey.GetPem()))
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("gcpkms: failed to decode public key: %w", err)
	}

	// https://cloud.google.com/kms/docs/reference/rpc/google.cloud.kms.v1#cryptokeyversionalgorithm
	switch t := pub.(type) {
	case *rsa.PublicKey:
	default:
		return nil, fmt.Errorf("gcpkms: unknown key type: %T", t)
	}

	return &Decrypter{
		name:   keyID,
		client: client,
		hash:   hasher,
		pub:    pub,
		algo:   algo,
		ctime:  key.CreateTime.AsTime(),
	}, nil
}

// Public returns the public key for the decrypter.
func (d *Decrypter) Public() crypto.PublicKey {
	return d.pub
}

// HashFunc returns the hash algorithm used for computing the digest.
func (d *Decrypter) HashFunc() crypto.Hash {
	return d.hash
}

// Algorithm returns KMS key algorithm. This only returns key algorithm.
func (d *Decrypter) Algorithm() cryptokms.Algorithm {
	return d.algo
}

// CreatedAt time at which key/key material was created.
// This is time at which KMS key version was created, not the key material.
func (d *Decrypter) CreatedAt() time.Time {
	return d.ctime
}

// context returns the context for this decrypter or
// if context is nil, returns [context.Background].
func (d *Decrypter) context() context.Context {
	d.mu.RLock()
	defer d.mu.RUnlock()

	ctx := d.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return ctx
}

// WithContext adds the given context to the decrypter.
func (d *Decrypter) WithContext(ctx context.Context) *Decrypter {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.ctx = ctx
	return d
}

// This is a wrapper around DecryptContext.
func (d *Decrypter) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return d.DecryptContext(d.context(), rand, ciphertext, opts)
}

// DecryptContext decrypts the message with asymmetric key.
func (d *Decrypter) DecryptContext(ctx context.Context, _ io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if d.client == nil || d.name == "" || d.pub == nil {
		return nil, fmt.Errorf("gcpkms: client not initialized")
	}

	// Fallback to default DecrypterOpts when no options are specified.
	// This is decrypter so, this fallback option is fine.
	// Exported Encrypt methods do not and should not support fallback.
	if opts == nil {
		opts = &rsa.OAEPOptions{
			Hash: d.hash,
		}
	}

	// Ensure hash is same as one supported by KMS key.
	switch v := opts.(type) {
	case nil:
	case *rsa.OAEPOptions:
		if v.Hash != d.hash {
			return nil, fmt.Errorf("gcpkms: invalid options, expected OAEPOptions.Hash=%s, got=%s", v.Hash, d.hash)
		}
		// return a helpful error if PKCS1v15DecryptOptions are specified.
	case *rsa.PKCS1v15DecryptOptions:
		return nil, fmt.Errorf(
			"gcpkms: PKCS1v15 encryption is not supported by GCP KMS use OAEP instead")
	default:
		return nil, fmt.Errorf("gcpkms: unknown DecrypterOpts type %T", opts)
	}

	// Decrypt the message
	resp, err := d.client.AsymmetricDecrypt(
		ctx,
		&kmspb.AsymmetricDecryptRequest{
			Name:             d.name,
			Ciphertext:       ciphertext,
			CiphertextCrc32C: computeCRC32(ciphertext),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("gcpkms: failed to decrypt: %w", err)
	}

	if !resp.VerifiedCiphertextCrc32C {
		return nil, fmt.Errorf("gcpkms: failed to decrypt, request corrupted in transit")
	}

	// Perform integrity verification (server response)
	plaintextCrc32 := computeCRC32(resp.Plaintext)
	if plaintextCrc32.Value != resp.PlaintextCrc32C.Value {
		return nil, fmt.Errorf("gcpkms: decryption data integrity error, expected CRC32=%x got=%x",
			resp.PlaintextCrc32C.Value, plaintextCrc32.Value)
	}
	return resp.Plaintext, nil
}
