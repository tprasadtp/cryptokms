// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

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

var (
	_ cryptokms.Signer  = (*Signer)(nil)
	_ crypto.Signer     = (*Signer)(nil)
	_ crypto.SignerOpts = (*Signer)(nil)
)

// Signer implements [crypto.Signer] interface backed by AWS KMS asymmetric key.
// Only keys with SIGN_VERIFY usage are supported.
//
//nolint:containedctx // ignore
type Signer struct {
	// Key ID is key ARN
	keyID   string
	ctx     context.Context
	mu      sync.RWMutex
	keySpec types.KeySpec
	// Signer can use different hashes
	// this maps crypto.Hash to SigningAlgorithmSpec
	// invalid signing algorithms are never populated.
	signingSpecMap map[crypto.Hash]types.SigningAlgorithmSpec
	defaultHasher  crypto.Hash // default hasher
	pub            crypto.PublicKey
	ctime          time.Time
	algo           cryptokms.Algorithm
	client         Client
}

// Returns a new signer backed by AWS KMS key which supports signing.
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
		return nil, fmt.Errorf("awskms: client is nil")
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

	// Ensure Key is enabled.
	if keyInfo.KeyMetadata.KeyState != types.KeyStateEnabled {
		return nil, fmt.Errorf("awskms: key(%s) is in unusable state - %s",
			*keyInfo.KeyMetadata.Arn,
			keyInfo.KeyMetadata.KeyState)
	}

	// Ensure KeyKeyUsage is SIGN_VERIFY
	if keyInfo.KeyMetadata.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("awskms: unsupported key usage(%s) for key(%s)",
			keyInfo.KeyMetadata.KeyUsage, keyID)
	}

	// Create new signer
	signer := &Signer{
		keyID:          *keyInfo.KeyMetadata.Arn,
		ctime:          *keyInfo.KeyMetadata.CreationDate,
		client:         client,
		keySpec:        keyInfo.KeyMetadata.KeySpec,
		signingSpecMap: make(map[crypto.Hash]types.SigningAlgorithmSpec),
	}

	switch keyInfo.KeyMetadata.KeySpec {
	case types.KeySpecRsa2048:
		signer.algo = cryptokms.AlgorithmRSA2048
	case types.KeySpecRsa3072:
		signer.algo = cryptokms.AlgorithmRSA3072
	case types.KeySpecRsa4096:
		signer.algo = cryptokms.AlgorithmRSA4096
	case types.KeySpecEccNistP256:
		signer.algo = cryptokms.AlgorithmECP256
	case types.KeySpecEccNistP384:
		signer.algo = cryptokms.AlgorithmECP384
	case types.KeySpecEccNistP521:
		signer.algo = cryptokms.AlgorithmECP521
	default:
		return nil, fmt.Errorf("awskms: unsupported key algorithm: %s",
			keyInfo.KeyMetadata.KeySpec)
	}

	// GetPublicKey
	getPublicKeyResp, err := client.GetPublicKey(ctx,
		&kms.GetPublicKeyInput{
			KeyId: keyInfo.KeyMetadata.Arn,
		})
	if err != nil {
		return nil, fmt.Errorf("awskms: failed to get public key for %s: %w",
			signer.keyID, err)
	}

	// Parse Public key and store it in signer.
	signer.pub, err = x509.ParsePKIXPublicKey(getPublicKeyResp.PublicKey)
	if err != nil {
		// This code path is not reachable, as KMS service always returns
		// valid DER keys when GetPublicKey does not return an error.
		return nil, fmt.Errorf("failed to parse public key DER: %w", err)
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
			signer.signingSpecMap[crypto.SHA512] = types.SigningAlgorithmSpecEcdsaSha512
		case types.SigningAlgorithmSpecEcdsaSha384:
			signer.signingSpecMap[crypto.SHA384] = types.SigningAlgorithmSpecEcdsaSha384
		case types.SigningAlgorithmSpecEcdsaSha256:
			signer.signingSpecMap[crypto.SHA256] = types.SigningAlgorithmSpecEcdsaSha256
		case types.SigningAlgorithmSpecRsassaPkcs1V15Sha256:
			signer.signingSpecMap[crypto.SHA256] = types.SigningAlgorithmSpecRsassaPkcs1V15Sha256
		case types.SigningAlgorithmSpecRsassaPkcs1V15Sha384:
			signer.signingSpecMap[crypto.SHA384] = types.SigningAlgorithmSpecRsassaPkcs1V15Sha384
		case types.SigningAlgorithmSpecRsassaPkcs1V15Sha512:
			signer.signingSpecMap[crypto.SHA512] = types.SigningAlgorithmSpecRsassaPkcs1V15Sha512
		}
	}
	// Ensure signer.hashToSigningAlgoMap has at-least one key.
	if len(signer.signingSpecMap) == 0 {
		return nil, fmt.Errorf("awskms: no supported signing algorithm for key(%s)",
			signer.keyID)
	}

	// Build default hasher.
	// If SHA56 is supported select it,
	// otherwise select a supported hashing algorithm.
	for _, item := range [3]crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		_, ok := signer.signingSpecMap[item]
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

// CreatedAt time at which KMS key was created.
func (s *Signer) CreatedAt() time.Time {
	return s.ctime
}

// Algorithm returns KMS key algorithm.
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

// Sign is a wrapper around SignContext.
func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.SignContext(s.context(), rand, digest, opts)
}

// SignContext signs the given digest with asymmetric key.
// The random parameter is ignored, and thus it can be as nil.
func (s *Signer) SignContext(ctx context.Context, _ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.client == nil || s.keyID == "" || s.pub == nil {
		return nil, fmt.Errorf("awskms: client not initialized")
	}

	// When no options are specified, use default provided by signer.
	if opts == nil {
		opts = s.HashFunc()
	}

	// Check if given hash function is supported by KMS key
	// If unsupported hash function is given, return a helpful message.
	if _, ok := s.signingSpecMap[opts.HashFunc()]; !ok {
		return nil, fmt.Errorf(
			"awskms: hash(%s) is not supported by key(%s), use(%s) instead",
			opts.HashFunc().String(), s.keyID, s.defaultHasher.String())
	}

	if len(digest) != opts.HashFunc().Size() {
		return nil, fmt.Errorf("awskms: digest length is %d, expected %d",
			len(digest), opts.HashFunc().Size())
	}

	// Sign Digest with KMS API.
	signatureResp, err := s.client.Sign(ctx,
		&kms.SignInput{
			KeyId:            &s.keyID,
			MessageType:      types.MessageTypeDigest,
			SigningAlgorithm: s.signingSpecMap[opts.HashFunc()],
			Message:          digest,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("awskms: failed to sign with key(%s): %w", s.keyID, err)
	}

	return signatureResp.Signature, nil
}
