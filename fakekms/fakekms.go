// Package fakekms implements crypto.Signer and crypto.Decrypter
// with ephemeral keys which are unique per execution of the binary.
//
//   - This package also provides a way to force returning errors on
//     sign/decrypt operation for use in integration or unit tests.
//   - This package should only be used in tests as keys are only
//     generated during init and are not rotated nor saved to any
//     persistent store.
package fakekms

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/tprasadtp/cryptokms"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

// Compile time check to ensure [Signer] implements
// [github.com/tprasadtp/cryptokms.Signer], [crypto.Signer]
// [github.com/tprasadtp/cryptokms.Decrypter],
// and [crypto.SignerOpts].
var (
	_ cryptokms.Signer  = (*SignerDecrypter)(nil)
	_ crypto.Decrypter  = (*SignerDecrypter)(nil)
	_ crypto.Signer     = (*SignerDecrypter)(nil)
	_ crypto.SignerOpts = (*SignerDecrypter)(nil)
)

// known TS.
var knownTS = time.Unix(1136239445, 0)

const (
	// ErrNotAvailable is returned when binary/test is built without fake tag.
	ErrNotAvailable = cryptokms.Error("cryptokms(fake): unavailable when built without fake tag")
)

// SignerDecrypter backed by an ephemeral key.
// Do not use these outside of tests.
type SignerDecrypter struct {
	ctx              context.Context
	mu               sync.RWMutex
	pub              crypto.PublicKey
	signer           crypto.Signer
	rsa              bool
	maxCiphertextLen int
	decrypter        crypto.Decrypter
	hash             crypto.Hash
	serr             bool
}

// Returns a new signer backed by a ephemeral test key.
// key can be one of
//   - rsa-2048
//   - rsa-3072
//   - rsa-4096
//   - ec-p256
//   - ec-p384
//   - ec-p521
//
// Do note that keys are generated during init and are unique per invocation of the binary.
func NewSigner(key string) (*SignerDecrypter, error) {
	s := SignerDecrypter{}
	switch strings.ToLower(strings.ReplaceAll(key, "_", "-")) {
	case "rsa-2048":
		s.signer = testkeys.GetRSA2048PrivateKey()
		s.pub = testkeys.GetRSA2048PublicKey()
		s.hash = crypto.SHA256
		s.rsa = true
	case "rsa-3072":
		s.signer = testkeys.GetRSA3072PrivateKey()
		s.pub = testkeys.GetRSA3072PublicKey()
		s.hash = crypto.SHA256
		s.rsa = true
	case "rsa-4096":
		s.signer = testkeys.GetRSA4096PrivateKey()
		s.pub = testkeys.GetRSA4096PublicKey()
		s.hash = crypto.SHA256
		s.rsa = true
	case "ec-p256", "ecc-p256", "ecc-nist-p256":
		s.signer = testkeys.GetECP256PrivateKey()
		s.pub = testkeys.GetECP256PublicKey()
		s.hash = crypto.SHA256
	case "ec-p384", "ecc-p384", "ecc-nist-p384":
		s.signer = testkeys.GetECP384PrivateKey()
		s.pub = testkeys.GetECP384PublicKey()
		s.hash = crypto.SHA384
	case "ec-p521", "ecc-p521", "ecc-nist-p521":
		s.signer = testkeys.GetECP521PrivateKey()
		s.pub = testkeys.GetECP521PublicKey()
		s.hash = crypto.SHA512
	default:
		return nil, fmt.Errorf("%w: fakekms: unsupported key - %s", cryptokms.ErrKeyAlgorithm, key)
	}
	return &s, nil
}

// Returns a decrypter backed by ephemeral in-memory key.
// key can be one of
//   - rsa-2048
//   - rsa-3072
//   - rsa-4096
//
// Do note that keys are generated during init and are unique per invocation of the binary.
func NewDecrypter(key string) (*SignerDecrypter, error) {
	s := SignerDecrypter{}
	switch strings.ToLower(strings.ReplaceAll(key, "_", "-")) {
	case "rsa-2048":
		s.decrypter = testkeys.GetRSA2048PrivateKey()
		s.pub = testkeys.GetRSA2048PublicKey()
		s.hash = crypto.SHA256
		s.maxCiphertextLen = 2048 / 8
		s.rsa = true
	case "rsa-3072":
		s.decrypter = testkeys.GetRSA3072PrivateKey()
		s.pub = testkeys.GetRSA3072PublicKey()
		s.hash = crypto.SHA256
		s.maxCiphertextLen = 3072 / 8
		s.rsa = true
	case "rsa-4096":
		s.decrypter = testkeys.GetRSA4096PrivateKey()
		s.pub = testkeys.GetRSA4096PublicKey()
		s.hash = crypto.SHA256
		s.maxCiphertextLen = 4096 / 8
		s.rsa = true
	default:
		return nil, fmt.Errorf("%w: fakekms: unsupported key - %s", cryptokms.ErrKeyAlgorithm, key)
	}
	return &s, nil
}

// Public returns the public key for the signer.
func (s *SignerDecrypter) Public() crypto.PublicKey {
	return s.pub
}

// Sets any sign/decrypt operation to always return an error.
// Returned error is always wrapped error cryptokms.ErrAsymmetricSign
// if its sign operation or cryptokms.ErrAsymmetricDecrypt if its decrypt operation.
func (s *SignerDecrypter) WithAlwaysError() *SignerDecrypter {
	s.serr = true
	return s
}

// HashFunc returns the default hash algorithm used for computing the digest.
// This ensures that signer also implements [crypto.SignerOptions].
func (s *SignerDecrypter) HashFunc() crypto.Hash {
	return s.hash
}

// SignerOpts returns sane default [crypto.SignerOpts].
func (s *SignerDecrypter) SignerOpts() crypto.SignerOpts {
	return s.hash
}

// Default decrypter options.
func (s *SignerDecrypter) DecrypterOpts() crypto.DecrypterOpts {
	return &rsa.OAEPOptions{
		Hash: s.hash,
	}
}

// CreatedAt always returns known timestamp.
func (s *SignerDecrypter) CreatedAt() time.Time {
	return knownTS
}

// context returns the context for this signer or
// if context is nil, returns [context.Background].
func (s *SignerDecrypter) context() context.Context {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return ctx
}

// WithContext adds the given context to the signer.
func (s *SignerDecrypter) WithContext(ctx context.Context) *SignerDecrypter {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ctx = ctx
	return s
}

// Returns KMS backend. This is always returns [github.com/tprasadtp/cryptokms.BackendFakeKMS].
func (s *SignerDecrypter) Backend() cryptokms.Backend {
	return cryptokms.BackendFakeKMS
}

// Sign is a wrapper around SignContext.
func (s *SignerDecrypter) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.SignContext(s.context(), rand, digest, opts)
}

// SignContext signs the given digest with asymmetric key.
// The random parameter is ignored, and thus it can be as nil.
func (s *SignerDecrypter) SignContext(ctx context.Context, random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.signer == nil || s.pub == nil {
		return nil, cryptokms.ErrInvalidKMSClient
	}

	if opts == nil {
		opts = s.SignerOpts()
	}

	if pss, ok := opts.(*rsa.PSSOptions); ok {
		// check if key is not RSA
		if !s.rsa {
			return nil, fmt.Errorf("%w: fakekms: cannot use rsa.PSSOptions when keys are not rsa",
				cryptokms.ErrSignerOpts)
		}

		// Use default fallback hash.
		if pss.Hash == 0 {
			pss.Hash = s.HashFunc()
		}

		// Some validations on PSS options
		// as there are additional restrictions are typically
		// placed by KMS provider like Salt length etc.
		if pss.SaltLength != pss.Hash.Size() {
			return nil, fmt.Errorf("%w: fakekms: salt length(%d) must be same as digest length(%d)",
				cryptokms.ErrSignerOpts, pss.SaltLength, pss.Hash.Size())
		}
	}

	if len(digest) != opts.HashFunc().Size() {
		return nil, fmt.Errorf("%w: fakekms: length is %d, want %d",
			cryptokms.ErrDigestLength, len(digest), opts.HashFunc().Size())
	}

	if s.serr {
		return nil, fmt.Errorf("%w: fakekms: signer is set to always return error",
			cryptokms.ErrAsymmetricSign)
	}

	sig, err := s.signer.Sign(random, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("%w: fakekms: signer error: %w", cryptokms.ErrAsymmetricSign, err)
	}
	return sig, nil
}

// Decrypt is a wrapper around DecryptContext.
func (s *SignerDecrypter) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return s.DecryptContext(s.context(), rand, ciphertext, opts)
}

// DecryptContext decrypts the message with asymmetric key.
// The rand parameter is ignored, and it can be nil.
func (s *SignerDecrypter) DecryptContext(ctx context.Context, rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if s.decrypter == nil || !s.rsa || s.pub == nil {
		return nil, cryptokms.ErrInvalidKMSClient
	}

	if opts == nil {
		opts = s.DecrypterOpts()
	}

	switch v := opts.(type) {
	case *rsa.OAEPOptions:
		// Ensure MGFHash is same as Hash when it is set to non zero value.
		if v.MGFHash != crypto.Hash(0) {
			if v.MGFHash != v.Hash {
				return nil, fmt.Errorf("%w: expected MGFHash=%s, but got=%s",
					cryptokms.ErrDigestAlgorithm, v.Hash, v.MGFHash)
			}
		}
	// return a helpful error if PKCS1v15DecryptOptions are specified.
	case *rsa.PKCS1v15DecryptOptions:
		return nil, fmt.Errorf("%w: PKCS1v15 encryption is not supported, use OAEP instead",
			cryptokms.ErrDecrypterOpts)
	default:
		return nil, fmt.Errorf("%w: unknown decrypter opts type %T", cryptokms.ErrDecrypterOpts, opts)
	}

	if len(ciphertext) > s.maxCiphertextLen {
		return nil, fmt.Errorf("%w: ciphertext cannot be larger than %d bytes",
			cryptokms.ErrPayloadTooLarge, s.maxCiphertextLen)
	}

	if s.serr {
		return nil, fmt.Errorf("%w: fakekms: decrypter is set to always return error",
			cryptokms.ErrAsymmetricDecrypt)
	}

	plaintext, err := s.decrypter.Decrypt(rand, ciphertext, opts)

	if err != nil {
		return nil, fmt.Errorf("%w: fakekms: failed to decrypt: %w",
			cryptokms.ErrAsymmetricDecrypt, err)
	}

	return plaintext, nil
}
