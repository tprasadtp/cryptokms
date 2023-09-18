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

var (
	_ cryptokms.Decrypter = (*Decrypter)(nil)
	_ crypto.Decrypter    = (*Decrypter)(nil)
)

// Decrypter backed by an ephemeral key.
// Do not use these outside of tests.
type Decrypter struct {
	ctx              context.Context
	mu               sync.RWMutex
	pub              crypto.PublicKey
	rsa              bool
	maxCiphertextLen int
	decrypter        crypto.Decrypter
	hash             crypto.Hash
	serr             bool
	algo             cryptokms.Algorithm
}

// Returns a decrypter backed by ephemeral in-memory key.
// key can be one of
//   - rsa-2048
//   - rsa-3072
//   - rsa-4096
//
// Do note that keys are generated on demand, stored in memory and are unique
// per invocation of the binary.
func NewDecrypter(key string) (*Decrypter, error) {
	s := Decrypter{}
	switch strings.ToLower(strings.ReplaceAll(key, "_", "-")) {
	case "rsa-2048":
		s.decrypter = testkeys.GetRSA2048PrivateKey()
		s.pub = testkeys.GetRSA2048PublicKey()
		s.hash = crypto.SHA256
		s.maxCiphertextLen = 2048 / 8
		s.rsa = true
		s.algo = cryptokms.AlgorithmRSA2048
	case "rsa-3072":
		s.decrypter = testkeys.GetRSA3072PrivateKey()
		s.pub = testkeys.GetRSA3072PublicKey()
		s.hash = crypto.SHA256
		s.maxCiphertextLen = 3072 / 8
		s.rsa = true
		s.algo = cryptokms.AlgorithmRSA3072
	case "rsa-4096":
		s.decrypter = testkeys.GetRSA4096PrivateKey()
		s.pub = testkeys.GetRSA4096PublicKey()
		s.hash = crypto.SHA256
		s.maxCiphertextLen = 4096 / 8
		s.rsa = true
		s.algo = cryptokms.AlgorithmRSA4096
	default:
		return nil, fmt.Errorf("%w: fakekms: unsupported key - %s", cryptokms.ErrKeyAlgorithm, key)
	}
	return &s, nil
}

// Public returns the public key for the signer.
func (s *Decrypter) Public() crypto.PublicKey {
	return s.pub
}

// Sets any sign/decrypt operation to always return an error.
// Returned error is always wrapped error cryptokms.ErrAsymmetricSign
// if its sign operation or cryptokms.ErrAsymmetricDecrypt if its decrypt operation.
func (s *Decrypter) WithAlwaysError() *Decrypter {
	s.serr = true
	return s
}

// HashFunc returns the default hash algorithm used for computing the digest.
// This ensures that signer also implements [crypto.SignerOptions].
func (s *Decrypter) HashFunc() crypto.Hash {
	return s.hash
}

// CreatedAt always returns known timestamp.
func (s *Decrypter) CreatedAt() time.Time {
	return knownTS
}

// Algorithm returns KMS key algorithm. This only returns key algorithm.
func (s *Decrypter) Algorithm() cryptokms.Algorithm {
	return s.algo
}

// context returns the context for this signer or
// if context is nil, returns [context.Background].
func (s *Decrypter) context() context.Context {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return ctx
}

// WithContext adds the given context to the signer.
func (s *Decrypter) WithContext(ctx context.Context) *Decrypter {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ctx = ctx
	return s
}

// Decrypt is a wrapper around DecryptContext.
func (s *Decrypter) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return s.DecryptContext(s.context(), rand, ciphertext, opts)
}

// DecryptContext decrypts the message with asymmetric key.
// The rand parameter is ignored, and it can be nil.
func (s *Decrypter) DecryptContext(ctx context.Context, rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if err := context.Cause(ctx); err != nil {
		return nil, fmt.Errorf("%w: fakekms: %w", cryptokms.ErrAsymmetricDecrypt, err)
	}

	if s.decrypter == nil || !s.rsa || s.pub == nil {
		return nil, cryptokms.ErrInvalidKMSClient
	}

	if opts == nil {
		opts = &rsa.OAEPOptions{
			Hash: s.hash,
		}
	}

	switch v := opts.(type) {
	case *rsa.OAEPOptions:
		// Ensure MGFHash is same as Hash when it is set to non zero value.
		if v.MGFHash != crypto.Hash(0) {
			if v.MGFHash != v.Hash {
				return nil, fmt.Errorf("%w: expected MGFHash=%s, but got=%s",
					cryptokms.ErrDecrypterOpts, v.Hash, v.MGFHash)
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
