package gcpkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
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

// Compile time check to ensure [Signer] implements
// [github.com/tprasadtp/cryptokms.Signer],
// [crypto.Signer] and [crypto.SignerOpts].
var (
	_ crypto.Signer     = (*Signer)(nil)
	_ crypto.SignerOpts = (*Signer)(nil)
	_ cryptokms.Signer  = (*Signer)(nil)
)

// Signer is backed by supported Google cloud KMS asymmetric key.
// RSA_SIGN_PSS_* and RSA_SIGN_RAW_* keys are not supported.
type Signer struct {
	name   string
	ctx    context.Context
	mu     sync.RWMutex
	pub    crypto.PublicKey
	hash   crypto.Hash
	ctime  time.Time
	client *kms.KeyManagementClient
	algo   cryptokms.Algorithm
}

// Returns a new signer backed by GCP KMS asymmetric key.
// Only following key types are supported.
//   - EC_SIGN_P256_SHA256
//   - EC_SIGN_P384_SHA384
//   - RSA_SIGN_PKCS1_2048_SHA256
//   - RSA_SIGN_PKCS1_3072_SHA256
//   - RSA_SIGN_PKCS1_4096_SHA256
//   - RSA_SIGN_PKCS1_4096_SHA512
//
// At minimum, following IAM permissions are required.
//   - cloudkms.cryptoKeyVersions.get
//   - cloudkms.cryptoKeyVersions.useToSign
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
//nolint:funlen
func NewSigner(ctx context.Context, keyID string, opts ...option.ClientOption) (*Signer, error) {
	// Create a new client
	client, err := kms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: gcpkms: failed to build kms client: %w",
			cryptokms.ErrInvalidKMSClient, err)
	}

	// Get key metadata.
	key, err := client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{Name: keyID})
	if err != nil {
		return nil, fmt.Errorf("%w: gcpkms: failed to get key version: %w", cryptokms.ErrGetKeyMetadata, err)
	}

	if key.State != kmspb.CryptoKeyVersion_ENABLED {
		return nil, fmt.Errorf("%w: gcpkms: key(%s) is in unusable sate - %s",
			cryptokms.ErrUnusableKeyState, keyID, key.State)
	}

	// Check key compatibility and hash algorithm.
	var hasher crypto.Hash
	var algo cryptokms.Algorithm

	switch key.Algorithm {
	// RSA PKCS1 SHA256
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256:
		hasher = crypto.SHA256
		algo = cryptokms.AlgorithmRSA2048
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256:
		hasher = crypto.SHA256
		algo = cryptokms.AlgorithmRSA3072
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256:
		hasher = crypto.SHA256
		algo = cryptokms.AlgorithmRSA4096
	// RSA SHA512 PKCS1
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512:
		hasher = crypto.SHA512
		algo = cryptokms.AlgorithmRSA4096
	// EC P256 with SHA256
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		hasher = crypto.SHA256
		algo = cryptokms.AlgorithmECP256
	// EC P256 with SHA384
	case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		hasher = crypto.SHA384
		algo = cryptokms.AlgorithmECP384
	// Unsupported Keys
	// -----------------------------------------------------------------------
	// RSS PSS keys are unsupported for signing operations for now
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512:
		return nil, fmt.Errorf("%w: gcpkms: pss key(%s) is not supported",
			cryptokms.ErrKeyAlgorithm, keyID)
	// EC_SIGN_SECP256K1_SHA256 is not supported.
	// This is due to golang's crypto libraries not implementing secp256k1.
	case kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256:
		return nil, fmt.Errorf("%w: gcpkms: secp256k1 key(%s) is not supported",
			cryptokms.ErrKeyAlgorithm, keyID)
	// Unsupported keys.
	case kmspb.CryptoKeyVersion_HMAC_SHA1,
		kmspb.CryptoKeyVersion_HMAC_SHA224,
		kmspb.CryptoKeyVersion_HMAC_SHA256,
		kmspb.CryptoKeyVersion_HMAC_SHA384,
		kmspb.CryptoKeyVersion_HMAC_SHA512:
		return nil, fmt.Errorf("%w: hmac key(%s) cannot be used for asymmetric signing",
			cryptokms.ErrKeyAlgorithm, keyID)
	case kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION:
		return nil, fmt.Errorf("%w: symmetric key(%s) cannot be used for asymmetric signing",
			cryptokms.ErrKeyAlgorithm, keyID)
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA1,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA1,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA1,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA512:
		return nil, fmt.Errorf("%w: decryption key(%s) cannot be used for asymmetric signing",
			cryptokms.ErrKeyAlgorithm, keyID)
	default:
		return nil, fmt.Errorf("%w: %s", cryptokms.ErrKeyAlgorithm, key.Algorithm)
	}

	// Retrieve the public key from KMS.
	pbPublicKey, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: keyID})
	if err != nil {
		return nil, fmt.Errorf("%w: gcpkms: failed to get public key: %w",
			cryptokms.ErrGetKeyMetadata, err)
	}

	// Verify response integrity.
	crcHash := ComputeCRC32([]byte(pbPublicKey.Pem))
	if crcHash.Value != pbPublicKey.PemCrc32C.Value {
		return nil, fmt.Errorf(
			"%w: %w: expected CRC32=%x got=%x",
			cryptokms.ErrGetKeyMetadata, ErrResponseIntegrity,
			pbPublicKey.PemCrc32C, crcHash.Value)
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
	case *ecdsa.PublicKey:
	default:
		return nil, fmt.Errorf("%w: %T", cryptokms.ErrKeyAlgorithm, t)
	}

	return &Signer{
		name:   keyID,
		client: client,
		hash:   hasher,
		pub:    pub,
		ctime:  key.CreateTime.AsTime(),
		algo:   algo,
	}, nil
}

// Public returns the public key for the signer.
func (s *Signer) Public() crypto.PublicKey {
	return s.pub
}

// HashFunc returns the hash algorithm used for computing the digest.
func (s *Signer) HashFunc() crypto.Hash {
	return s.hash
}

// CreatedAt time at which key was created.
// This is time at which KMS key version was created, not the key material.
func (s *Signer) CreatedAt() time.Time {
	return s.ctime
}

// Algorithm returns KMS key algorithm. This only returns key algorithm.
func (s *Signer) Algorithm() cryptokms.Algorithm {
	return s.algo
}

// context returns the context for this signer or
// if context is nil, returns [context.Background].
func (s *Signer) context() context.Context {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return ctx
}

// WithContext adds the given context to the signer.
func (s *Signer) WithContext(ctx context.Context) *Signer {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ctx = ctx
	return s
}

// This is a wrapper around SignContext.
func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.SignContext(s.context(), rand, digest, opts)
}

// SignContext signs the digest with asymmetric key.
// Due to nature of GCP KMS, [crypto.SignerOpts] must match key's algorithm or it must be nil.
func (s *Signer) SignContext(ctx context.Context, _ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.client == nil || s.name == "" || s.pub == nil {
		return nil, cryptokms.ErrInvalidKMSClient
	}

	if opts != nil {
		if opts.HashFunc() != s.hash {
			return nil, fmt.Errorf("%w: gcpkms: algorithm is %s, but want %s", cryptokms.ErrDigestAlgorithm, opts.HashFunc(), s.hash)
		}
	}

	if len(digest) != s.hash.Size() {
		return nil, fmt.Errorf("%w: gcpkms: length is %d, want %d", cryptokms.ErrDigestLength, len(digest), s.hash.Size())
	}

	// Set the correct digest based on the key's digest algorithm
	var digestpb *kmspb.Digest
	switch s.hash {
	case crypto.SHA256:
		digestpb = &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest}}
	case crypto.SHA384:
		digestpb = &kmspb.Digest{Digest: &kmspb.Digest_Sha384{Sha384: digest}}
	case crypto.SHA512:
		digestpb = &kmspb.Digest{Digest: &kmspb.Digest_Sha512{Sha512: digest}}
	default:
		return nil, fmt.Errorf("%w: %s", cryptokms.ErrDigestAlgorithm, s.hash)
	}

	// Sign the digest
	resp, err := s.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name:         s.name,
		Digest:       digestpb,
		DigestCrc32C: ComputeCRC32(digest),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", cryptokms.ErrAsymmetricSign, err)
	}

	// Perform integrity verification (server side)
	if !resp.VerifiedDigestCrc32C {
		return nil, ErrRequestIntegrity
	}

	// Perform integrity verification (server response)
	respCrc32Hash := ComputeCRC32(resp.Signature)
	if respCrc32Hash.Value != resp.SignatureCrc32C.Value {
		return nil, fmt.Errorf(
			"%w: gcpkms: expected CRC32=%x got=%x",
			ErrResponseIntegrity, resp.SignatureCrc32C.Value, respCrc32Hash.Value)
	}

	return resp.Signature, nil
}
