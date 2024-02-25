// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package awskms

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/tprasadtp/cryptokms"
)

var (
	_ cryptokms.Decrypter = (*Decrypter)(nil)
	_ crypto.Decrypter    = (*Decrypter)(nil)
)

// Decrypter implements [crypto.Decrypter] interface backed by AWS KMS asymmetric key.
// Only keys with ENCRYPT_DECRYPT usage are supported.
//
//nolint:containedctx // ignore
type Decrypter struct {
	keyID   string // key ARN
	ctx     context.Context
	mu      sync.RWMutex
	keySpec types.KeySpec
	// decrypter can use different hashes
	// this maps crypto.Hash to EncryptionAlgorithmSpec
	// invalid decryption algorithms are never populated.
	hashToEncryptionAlgoMap map[crypto.Hash]types.EncryptionAlgorithmSpec
	// default hashing algorithm.
	defaultHasher    crypto.Hash
	maxCiphertextLen int
	pub              crypto.PublicKey
	ctime            time.Time
	algo             cryptokms.Algorithm
	client           Client
}

// Returns a new signer backed by AWS KMS asymmetric key which supports signing.
// keyID must be either key ARN or key alias ARN.
//   - Key Usage MUST be set to ENCRYPT_DECRYPT.
//
// Following key specs(algorithms) are supported.
//   - RSA_2048
//   - RSA_3072
//   - RSA_4096
//
// Following encryption algorithms are supported.
//   - RSAES_OAEP_SHA_1
//   - RSAES_OAEP_SHA_256
//
// Following IAM Actions must be allowed on the key by the caller.
//   - kms:Decrypt
//   - kms:DescribeKey
//   - kms:GetPublicKey
//
// See https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html for more info.
func NewDecrypter(ctx context.Context, client Client, keyID string) (*Decrypter, error) {
	if client == nil {
		return nil, fmt.Errorf("awskms: client not initialized")
	}

	keyInfo, err := client.DescribeKey(
		ctx,
		&kms.DescribeKeyInput{
			KeyId: &keyID,
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"awskms: failed to describe key: %w", err)
	}

	// Ensure KeyState is valid and enabled
	if keyInfo.KeyMetadata.KeyState != types.KeyStateEnabled {
		return nil, fmt.Errorf("awskms: key(%s) is in unusable state - %s",
			*keyInfo.KeyMetadata.Arn,
			keyInfo.KeyMetadata.KeyState)
	}

	// Ensure KeyKeyUsage is ENCRYPT_DECRYPT
	if keyInfo.KeyMetadata.KeyUsage != types.KeyUsageTypeEncryptDecrypt {
		return nil, fmt.Errorf("awskms: unsupported key usage(%s) for key(%s)",
			keyInfo.KeyMetadata.KeyUsage, keyID)
	}

	// Create new decrypter
	decrypter := &Decrypter{
		keyID:         *keyInfo.KeyMetadata.Arn,
		ctime:         *keyInfo.KeyMetadata.CreationDate,
		client:        client,
		keySpec:       keyInfo.KeyMetadata.KeySpec,
		defaultHasher: crypto.SHA256, // defaults to RSA OAEP SHA256
		//nolint:exhaustive // not all hashes are supported.
		hashToEncryptionAlgoMap: map[crypto.Hash]types.EncryptionAlgorithmSpec{
			crypto.SHA1:   types.EncryptionAlgorithmSpecRsaesOaepSha1,
			crypto.SHA256: types.EncryptionAlgorithmSpecRsaesOaepSha256,
		},
	}

	// GetPublicKey
	getPublicKeyResp, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: keyInfo.KeyMetadata.Arn})
	if err != nil {
		return nil, fmt.Errorf("awskms: failed to get public key for %s: %w",
			decrypter.keyID, err)
	}

	// Parse Public key and store it in signer.
	decrypter.pub, err = x509.ParsePKIXPublicKey(getPublicKeyResp.PublicKey)
	if err != nil {
		// This code path is not reachable, as KMS service always returns
		// valid DER keys when GetPublicKey does not return an error.
		return nil, fmt.Errorf("failed to parse public key DER: %w", err)
	}

	// maxCiphertextLen is key modulus.
	//
	//nolint:exhaustive // other encryption KeySpecs do not support asymmetric encryption.
	switch keyInfo.KeyMetadata.KeySpec {
	case types.KeySpecRsa2048:
		decrypter.maxCiphertextLen = 2048 / 8
		decrypter.algo = cryptokms.AlgorithmRSA2048
	case types.KeySpecRsa3072:
		decrypter.maxCiphertextLen = 3072 / 8
		decrypter.algo = cryptokms.AlgorithmRSA3072
	case types.KeySpecRsa4096:
		decrypter.maxCiphertextLen = 4096 / 8
		decrypter.algo = cryptokms.AlgorithmRSA4096
	}

	return decrypter, nil
}

// Public returns the public key for the signer.
func (d *Decrypter) Public() crypto.PublicKey {
	return d.pub
}

// HashFunc returns the default hash algorithm used for computing the digest.
// If underlying KMS key supports multiple hashes, defaults to best suitable hash.
// In most AWSKMS cases when multiple decryption algorithms are supported,
// this is [crypto.SHA256].
func (d *Decrypter) HashFunc() crypto.Hash {
	return d.defaultHasher
}

// CreatedAt time at which KMS key was created.
func (d *Decrypter) CreatedAt() time.Time {
	return d.ctime
}

// Algorithm returns KMS key algorithm.
func (d *Decrypter) Algorithm() cryptokms.Algorithm {
	return d.algo
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
// The rand parameter is ignored, and it can be nil.
func (d *Decrypter) DecryptContext(ctx context.Context, _ io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if d.client == nil || d.keyID == "" || d.pub == nil {
		return nil, fmt.Errorf("awskms: client not initialized")
	}

	// Fallback to default DecrypterOpts when no options are specified.
	// This is decrypter so, this fallback option is fine.
	// Exported Encrypt methods do not and should not support fallback.
	if opts == nil {
		opts = &rsa.OAEPOptions{
			Hash: d.defaultHasher,
		}
	}

	// Hash Options for looking up EncryptionAlgorithm.
	var hasher crypto.Hash

	// Ensure hash is same as one supported by KMS key.
	switch v := opts.(type) {
	case *rsa.OAEPOptions:
		if _, ok := d.hashToEncryptionAlgoMap[v.Hash]; !ok {
			return nil, fmt.Errorf("awskms: hash %s is not supported by KMS key(%s)",
				v.Hash, d.keyID)
		}
		hasher = v.Hash

		// Ensure MGFHash is same as Hash when it is set to non zero value.
		if v.MGFHash != crypto.Hash(0) {
			if v.MGFHash != v.Hash {
				return nil, fmt.Errorf("awskms: invalid options, expected MGFHash=%s, but got=%s",
					v.Hash, v.MGFHash)
			}
		}
	// return a helpful error if PKCS1v15DecryptOptions are specified.
	case *rsa.PKCS1v15DecryptOptions:
		return nil, fmt.Errorf(
			"awskms: invalid option, PKCS1v15 is not supported by AWS KMS use OAEP instead")
	default:
		return nil, fmt.Errorf("awskms: unknown decrypter opts type %T", opts)
	}

	if len(ciphertext) > d.maxCiphertextLen {
		return nil, fmt.Errorf("awskms: ciphertext cannot be larger than %d bytes",
			d.maxCiphertextLen)
	}

	decryptResp, err := d.client.Decrypt(ctx,
		&kms.DecryptInput{
			KeyId:               &d.keyID,
			CiphertextBlob:      ciphertext,
			EncryptionAlgorithm: d.hashToEncryptionAlgoMap[hasher],
		},
	)
	if err != nil {
		return nil, fmt.Errorf("awskms: failed to decrypt with key(%s): %w",
			d.keyID, err)
	}

	return decryptResp.Plaintext, nil
}
