package awskms

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/tprasadtp/cryptokms"
)

// Compile time check to ensure [Signer] implements
// [github.com/tprasadtp/cryptokms.Signer],
// [crypto.Signer] and [crypto.SignerOpts].
var (
	_ cryptokms.Signer  = (*Signer)(nil)
	_ crypto.Signer     = (*Signer)(nil)
	_ crypto.SignerOpts = (*Signer)(nil)
)

// Signer implements [crypto.Signer] interface backed by AWS KMS asymmetric key.
// Only keys with SIGN_VERIFY usage are supported.
type Signer struct {
	// Key ID is key ARN
	keyID   string
	ctx     context.Context
	mu      sync.RWMutex
	keySpec types.KeySpec
	// signer can use different hashes
	// this maps crypto.Hash to SigningAlgorithmSpec
	// invalid signing algorithms are never populated.
	hashToSigningAlgoMap map[crypto.Hash]types.SigningAlgorithmSpec
	// default hashing algorithm.
	defaultHasher crypto.Hash
	pub           crypto.PublicKey
	ctime         time.Time
	client        Client
}

// Returns a new signer backed by AWS KMS asymmetric key which supports signing.
// keyID must be either key ARN or key alias ARN.
//   - Key Usage MUST be set to SIGN_VERIFY.
//
// Following key specs(algorithms) are supported.
//   - RSA_2048
//   - RSA_3072
//   - RSA_4096
//   - ECC_NIST_P256
//   - ECC_NIST_P384
//   - ECC_NIST_P521
//
// Following IAM Actions must be allowed on the key by the caller.
//   - kms:Sign
//   - kms:DescribeKey
//   - kms:GetPublicKey
//
// See https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html for more info.
func NewSigner(ctx context.Context, client Client, keyID string) (*Signer, error) {
	if client == nil {
		return nil, cryptokms.ErrInvalidKMSClient
	}

	keyInfo, err := client.DescribeKey(
		ctx,
		&kms.DescribeKeyInput{
			KeyId: &keyID,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("%w: awskms: failed to describe key: %w", cryptokms.ErrGetKeyMetadata, err)
	}

	// Ensure KeyState is valid and enabled
	if keyInfo.KeyMetadata.KeyState != types.KeyStateEnabled {
		return nil, fmt.Errorf("%w: awskms: key(%s) unusable key state - %s",
			cryptokms.ErrUnusableKeyState,
			*keyInfo.KeyMetadata.Arn,
			keyInfo.KeyMetadata.KeyState)
	}

	// Ensure KeyKeyUsage is SIGN_VERIFY
	switch keyInfo.KeyMetadata.KeyUsage {
	case types.KeyUsageTypeSignVerify:
	case types.KeyUsageTypeEncryptDecrypt:
		return nil, fmt.Errorf("%w: awskms: encryption key(%s) cannot be used for asymmetric signing",
			cryptokms.ErrUnsupportedMethod, keyID)
	case types.KeyUsageTypeGenerateVerifyMac:
		return nil, fmt.Errorf("%w: awskms: HMAC key(%s) cannot be used for asymmetric signing",
			cryptokms.ErrUnsupportedMethod, keyID)
	default:
		return nil, fmt.Errorf("%w: awskms: unsupported key usage(%s) for key(%s)",
			cryptokms.ErrKeyAlgorithm, keyInfo.KeyMetadata.KeyUsage, keyID)
	}

	// Create new signer
	signer := &Signer{
		keyID:                *keyInfo.KeyMetadata.Arn,
		ctime:                *keyInfo.KeyMetadata.CreationDate,
		client:               client,
		keySpec:              keyInfo.KeyMetadata.KeySpec,
		hashToSigningAlgoMap: make(map[crypto.Hash]types.SigningAlgorithmSpec),
	}

	// GetPublicKey
	getPublicKeyResp, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: keyInfo.KeyMetadata.Arn})
	if err != nil {
		return nil, fmt.Errorf("%w : awskms: failed to get public key for %s: %w",
			cryptokms.ErrGetKeyMetadata, signer.keyID, err)
	}

	// Parse Public key and store it in signer.
	signer.pub, err = x509.ParsePKIXPublicKey(getPublicKeyResp.PublicKey)
	if err != nil {
		// This code path is not reachable, as KMS service always returns
		// valid DER keys when GetPublicKey does not return an error.
		return nil, fmt.Errorf("%w: failed to parse public key DER: %w",
			cryptokms.ErrGetKeyMetadata, err)
	}

	// KMS keys only support certain signing (thus digest) algorithms.
	// This iterates over all supported signing algorithms,
	// and builds a map of [crypto.Hash] -> SigningAlgorithmSpec
	// unsupported signing algorithms are not populated in the map.
	// Thus signer can simply lookup its digest type or signerOpts
	// and use KMS API directly for signing.
	for _, item := range getPublicKeyResp.SigningAlgorithms {
		//nolint:exhaustive // other signing algorithms are unsupported. ignore them.
		switch item {
		case types.SigningAlgorithmSpecEcdsaSha512:
			signer.hashToSigningAlgoMap[crypto.SHA512] = types.SigningAlgorithmSpecEcdsaSha512
		case types.SigningAlgorithmSpecEcdsaSha384:
			signer.hashToSigningAlgoMap[crypto.SHA384] = types.SigningAlgorithmSpecEcdsaSha384
		case types.SigningAlgorithmSpecEcdsaSha256:
			signer.hashToSigningAlgoMap[crypto.SHA256] = types.SigningAlgorithmSpecEcdsaSha256
		case types.SigningAlgorithmSpecRsassaPkcs1V15Sha256:
			signer.hashToSigningAlgoMap[crypto.SHA256] = types.SigningAlgorithmSpecRsassaPkcs1V15Sha256
		case types.SigningAlgorithmSpecRsassaPkcs1V15Sha384:
			signer.hashToSigningAlgoMap[crypto.SHA384] = types.SigningAlgorithmSpecRsassaPkcs1V15Sha384
		case types.SigningAlgorithmSpecRsassaPkcs1V15Sha512:
			signer.hashToSigningAlgoMap[crypto.SHA512] = types.SigningAlgorithmSpecRsassaPkcs1V15Sha512
		}
	}
	// Ensure signer.hashToSigningAlgoMap has at-least one key.
	if len(signer.hashToSigningAlgoMap) == 0 {
		return nil, fmt.Errorf("%w: no supported signing algorithm for key(%s)",
			cryptokms.ErrDigestAlgorithm, signer.keyID)
	}

	// Build default hasher.
	// If SHA56 is supported select it,
	// otherwise select a supported hashing algorithm.
	for _, item := range [3]crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		_, ok := signer.hashToSigningAlgoMap[item]
		if ok {
			signer.defaultHasher = item
			break
		}
	}

	return signer, nil
}

// Public returns the public key for the signer.
func (s *Signer) Public() crypto.PublicKey {
	return s.pub
}

// HashFunc returns the default hash algorithm used for computing the digest.
// If multiple signing algorithms are supported, this returns sane default,
// typically [crypto.SHA256].
func (s *Signer) HashFunc() crypto.Hash {
	return s.defaultHasher
}

// DecrypterOpts Returns a valid signer option suitable for using with Sign interface.
// If multiple signing algorithms are supported, this returns sane default,
// typically RSA PKCS1v5 with [crypto.SHA256].
func (s *Signer) SignerOpts() crypto.SignerOpts {
	return s.defaultHasher
}

// CreatedAt time at which KMS key was created.
func (s *Signer) CreatedAt() time.Time {
	return s.ctime
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

// Returns KMS backend. This is always returns [github.com/tprasadtp/cryptokms.BackendAWSKMS].
func (s *Signer) Backend() cryptokms.Backend {
	return cryptokms.BackendAWSKMS
}

// Sign is a wrapper around SignContext.
func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.SignContext(s.context(), rand, digest, opts)
}

// SignContext signs the given digest with asymmetric key.
// The random parameter is ignored, and thus it can be as nil.
func (s *Signer) SignContext(ctx context.Context, rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.client == nil || s.keyID == "" || s.pub == nil {
		return nil, cryptokms.ErrInvalidKMSClient
	}

	// When no options are specified, use default provided by signer.
	if opts == nil {
		opts = s.SignerOpts()
	}

	// Check if given hash function is supported by KMS key
	// If unsupported hash function is given, return a helpful message.
	if _, ok := s.hashToSigningAlgoMap[opts.HashFunc()]; !ok {
		return nil, fmt.Errorf("%w: awskms: hash(%s) is not supported by key(%s), use(%s) instead",
			cryptokms.ErrDigestAlgorithm, opts.HashFunc().String(), s.keyID, s.defaultHasher.String())
	}

	if len(digest) != opts.HashFunc().Size() {
		return nil, fmt.Errorf("%w: length is %d, want %d", cryptokms.ErrDigestLength, len(digest), opts.HashFunc().Size())
	}

	// Sign Digest with KMS API.
	signatureResp, err := s.client.Sign(ctx,
		&kms.SignInput{
			KeyId:            &s.keyID,
			MessageType:      types.MessageTypeDigest,
			SigningAlgorithm: s.hashToSigningAlgoMap[opts.HashFunc()],
			Message:          digest,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("%w: awskms: failed to sign with key(%s): %w",
			cryptokms.ErrAsymmetricSign, s.keyID, err)
	}

	return signatureResp.Signature, nil
}
