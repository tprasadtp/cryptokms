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
)

// Compile time check to ensure [Decrypter] implements
// [github.com/tprasadtp/cryptokms.Signer] and [crypto.Decrypter].
var (
	_ cryptokms.Decrypter = (*Decrypter)(nil)
	_ crypto.Decrypter    = (*Decrypter)(nil)
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
type Decrypter struct {
	name   string
	ctx    context.Context
	mu     sync.RWMutex
	pub    crypto.PublicKey
	hash   crypto.Hash
	ctime  time.Time
	client *kms.KeyManagementClient
}

// Returns a new Decrypter backed by GCP KMS asymmetric key.
func NewDecrypter(ctx context.Context, client *kms.KeyManagementClient, keyID string) (*Decrypter, error) {
	if client == nil {
		return nil, cryptokms.ErrInvalidKMSClient
	}

	// Get key metadata.
	key, err := client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{Name: keyID})
	if err != nil {
		return nil, fmt.Errorf("%w: gcpkms: failed to get key version: %w",
			cryptokms.ErrGetKeyMetadata, err)
	}

	if key.State != kmspb.CryptoKeyVersion_ENABLED {
		return nil, fmt.Errorf("%w: %s", cryptokms.ErrUnusableKeyState, key.State)
	}

	// Check key compatibility and hash algorithm.
	var hasher crypto.Hash
	switch key.Algorithm {
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA1:
		hasher = crypto.SHA1
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA1:
		hasher = crypto.SHA1
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA1:
		hasher = crypto.SHA1
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256:
		hasher = crypto.SHA256
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256:
		hasher = crypto.SHA256
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256:
		hasher = crypto.SHA256
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA512:
		hasher = crypto.SHA512
	// Unsupported Methods
	case kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
		kmspb.CryptoKeyVersion_HMAC_SHA1,
		kmspb.CryptoKeyVersion_HMAC_SHA224,
		kmspb.CryptoKeyVersion_HMAC_SHA256,
		kmspb.CryptoKeyVersion_HMAC_SHA384,
		kmspb.CryptoKeyVersion_HMAC_SHA512,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512,
		kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		return nil, fmt.Errorf("%w : %s", cryptokms.ErrUnsupportedMethod, key.Algorithm.String())
	default:
		return nil, fmt.Errorf("%w : %s", cryptokms.ErrKeyAlgorithm, key.Algorithm.String())
	}

	// Retrieve the public key from KMS.
	pbPublicKey, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: keyID})
	if err != nil {
		return nil, fmt.Errorf("gcpkms: failed to get public key: %w", err)
	}

	// Verify response integrity.
	crcHash := ComputeCRC32([]byte(pbPublicKey.Pem))
	if crcHash.Value != pbPublicKey.PemCrc32C.Value {
		return nil, fmt.Errorf(
			"%w: expected CRC32=%x got=%x",
			ErrResponseIntegrity, pbPublicKey.PemCrc32C, crcHash.Value)
	}

	// Parse public key PEM
	block, _ := pem.Decode([]byte(pbPublicKey.GetPem()))
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("gcpkms: failed to parse public key: %w", err)
	}

	// https://cloud.google.com/kms/docs/reference/rpc/google.cloud.kms.v1#cryptokeyversionalgorithm
	switch t := pub.(type) {
	case *rsa.PublicKey:
	default:
		return nil, fmt.Errorf("%w: not *rsa.PublicKey, %T", cryptokms.ErrKeyAlgorithm, t)
	}

	return &Decrypter{
		name:   keyID,
		client: client,
		hash:   hasher,
		pub:    pub,
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

// DecrypterOpts returns supported DecrypterOpts options.
func (d *Decrypter) DecrypterOpts() crypto.DecrypterOpts {
	return &rsa.OAEPOptions{
		Hash: d.hash,
	}
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

// Returns KMS backend. This is always [github.com/tprasadtp/cryptokms.BackendGoogleCloudKMS].
func (d *Decrypter) Backend() cryptokms.Backend {
	return cryptokms.BackendGoogleCloudKMS
}

// This is a wrapper around DecryptContext.
func (d *Decrypter) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return d.DecryptContext(d.context(), rand, ciphertext, opts)
}

// DecryptContext decrypts the message with asymmetric key.
func (d *Decrypter) DecryptContext(ctx context.Context, _ io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if d.client == nil || d.name == "" || d.pub == nil {
		return nil, cryptokms.ErrInvalidKMSClient
	}

	// Ensure hash is same as one supported by KMS key.
	switch v := opts.(type) {
	case nil:
	case *rsa.OAEPOptions:
		if v.Hash != d.hash {
			return nil, fmt.Errorf("%w: expected OAEPOptions.Hash=%s, got=%s", cryptokms.ErrDigestAlgorithm, v.Hash, d.hash)
		}
	default:
		return nil, fmt.Errorf("%w: unknown DecrypterOpts type %T", cryptokms.ErrAsymmetricDecrypt, opts)
	}

	// Decrypt the message
	resp, err := d.client.AsymmetricDecrypt(
		ctx,
		&kmspb.AsymmetricDecryptRequest{
			Name:             d.name,
			Ciphertext:       ciphertext,
			CiphertextCrc32C: ComputeCRC32(ciphertext),
		},
	)

	if err != nil {
		return nil, fmt.Errorf("%w: %w", cryptokms.ErrAsymmetricDecrypt, err)
	}

	if !resp.VerifiedCiphertextCrc32C {
		return nil, ErrRequestIntegrity
	}

	// Perform integrity verification (server response)
	plaintextCrc32 := ComputeCRC32(resp.Plaintext)
	if plaintextCrc32.Value != resp.PlaintextCrc32C.Value {
		return nil, fmt.Errorf(
			"%w: expected CRC32=%x got=%x",
			ErrResponseIntegrity, resp.PlaintextCrc32C.Value, plaintextCrc32.Value)
	}
	return resp.Plaintext, nil
}
