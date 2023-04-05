// Package filekms implements crypto.Signer and crypto.Decrypter
// with keys backed by filesystem storage. This is insecure
// unless additional steps are taken. (using a ramfs with systemd credentials,
// or kubernetes projected volumes or etc).
package filekms

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/tprasadtp/cryptokms"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

// Compile time check to ensure [Signer] implements
// [github.com/tprasadtp/cryptokms.Signer],
// [crypto.Signer] and [crypto.SignerOpts].
var (
	_ cryptokms.Signer  = (*SignerDecrypter)(nil)
	_ crypto.Signer     = (*SignerDecrypter)(nil)
	_ crypto.SignerOpts = (*SignerDecrypter)(nil)
)

// known TS.
var knownTS = time.Unix(1136239445, 0)

const (
	// ErrNotAvailable is returned when binary/test is built without fake tag.
	ErrNotAvailable = cryptokms.Error("cryptokms(fake): unavailable when built without fake tag")
)

// SignerDecrypter backed by an insecure well known in-memory key.
// Do not use these outside of tests.
type SignerDecrypter struct {
	ctx       context.Context
	mu        sync.RWMutex
	pub       crypto.PublicKey
	signer    crypto.Signer
	decrypter crypto.Decrypter
	hash      crypto.Hash
	serr      bool
}

// Returns a Signer backed by well known insecure key.
func NewSigner(key string) (*SignerDecrypter, error) {
	s := SignerDecrypter{}
	switch strings.ToLower(strings.ReplaceAll(key, "_", "-")) {
	case "rsa-2048":
		s.signer = testkeys.GetRSA2048PrivateKey()
		s.pub = testkeys.GetRSA2048PublicKey()
		s.hash = crypto.SHA256
	case "rsa-3072":
		s.signer = testkeys.GetRSA3072PrivateKey()
		s.pub = testkeys.GetRSA3072PublicKey()
		s.hash = crypto.SHA256
	case "rsa-4096":
		s.signer = testkeys.GetRSA4096PrivateKey()
		s.pub = testkeys.GetRSA4096PublicKey()
		s.hash = crypto.SHA256
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

// Returns a decrypter backed by well known insecure key.
func NewDecrypter(key string) (*SignerDecrypter, error) {
	s := SignerDecrypter{}
	switch strings.ToLower(strings.ReplaceAll(key, "_", "-")) {
	case "rsa-2048":
		s.signer = testkeys.GetRSA2048PrivateKey()
		s.pub = testkeys.GetRSA2048PublicKey()
		s.hash = crypto.SHA256
	case "rsa-3072":
		s.signer = testkeys.GetRSA3072PrivateKey()
		s.pub = testkeys.GetRSA3072PublicKey()
		s.hash = crypto.SHA256
	case "rsa-4096":
		s.signer = testkeys.GetRSA4096PrivateKey()
		s.pub = testkeys.GetRSA4096PublicKey()
		s.hash = crypto.SHA256
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
// Returned error is always wrapped error cryptokms.ErrAsymmetricSign.
// if its sign operation or cryptokms.ErrAsymmetricDecrypt if its decrypt operation.
func (s *SignerDecrypter) WithAlwaysError() *SignerDecrypter {
	s.serr = true
	return s
}

// HashFunc returns the default hash algorithm used for computing the digest.
func (s *SignerDecrypter) HashFunc() crypto.Hash {
	return s.hash
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
//
// Deprecated: Use SignContext/DecryptContext instead.
func (s *SignerDecrypter) WithContext(ctx context.Context) *SignerDecrypter {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ctx = ctx
	return s
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

	if s.serr {
		return nil, fmt.Errorf("%w: fakekms: signer is set to always return error", cryptokms.ErrAsymmetricSign)
	}

	// When no options are specified, use default hashing algorithm.
	// and when specified, ensure specified digest matches the options.
	if opts == nil {
		opts = s.HashFunc()
	}

	if len(digest) != s.hash.Size() {
		return nil, fmt.Errorf("%w: fakekms: length is %d, want %d",
			cryptokms.ErrDigestLength, len(digest), s.hash.Size())
	}

	sig, err := s.signer.Sign(random, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("%w: fakekms: signer error: %w", cryptokms.ErrAsymmetricSign, err)
	}
	return sig, nil
}
