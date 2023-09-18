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
	_ cryptokms.Signer  = (*Signer)(nil)
	_ crypto.Signer     = (*Signer)(nil)
	_ crypto.SignerOpts = (*Signer)(nil)
)

// Signer backed by an ephemeral key.
// Do not use these outside of tests.
type Signer struct {
	ctx    context.Context
	mu     sync.RWMutex
	pub    crypto.PublicKey
	signer crypto.Signer
	rsa    bool
	hash   crypto.Hash
	serr   bool
	algo   cryptokms.Algorithm
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
func NewSigner(key string) (*Signer, error) {
	s := Signer{}
	switch strings.ToLower(strings.ReplaceAll(key, "_", "-")) {
	case "rsa-2048":
		s.signer = testkeys.GetRSA2048PrivateKey()
		s.pub = testkeys.GetRSA2048PublicKey()
		s.hash = crypto.SHA256
		s.rsa = true
		s.algo = cryptokms.AlgorithmRSA2048
	case "rsa-3072":
		s.signer = testkeys.GetRSA3072PrivateKey()
		s.pub = testkeys.GetRSA3072PublicKey()
		s.hash = crypto.SHA256
		s.rsa = true
		s.algo = cryptokms.AlgorithmRSA3072
	case "rsa-4096":
		s.signer = testkeys.GetRSA4096PrivateKey()
		s.pub = testkeys.GetRSA4096PublicKey()
		s.hash = crypto.SHA256
		s.rsa = true
		s.algo = cryptokms.AlgorithmRSA4096
	case "ec-p256", "ecc-p256", "ecc-nist-p256":
		s.signer = testkeys.GetECP256PrivateKey()
		s.pub = testkeys.GetECP256PublicKey()
		s.hash = crypto.SHA256
		s.algo = cryptokms.AlgorithmECP256
	case "ec-p384", "ecc-p384", "ecc-nist-p384":
		s.signer = testkeys.GetECP384PrivateKey()
		s.pub = testkeys.GetECP384PublicKey()
		s.hash = crypto.SHA384
		s.algo = cryptokms.AlgorithmECP384
	case "ec-p521", "ecc-p521", "ecc-nist-p521":
		s.signer = testkeys.GetECP521PrivateKey()
		s.pub = testkeys.GetECP521PublicKey()
		s.hash = crypto.SHA512
		s.algo = cryptokms.AlgorithmECP521
	default:
		return nil, fmt.Errorf("%w: fakekms: unsupported key - %s", cryptokms.ErrKeyAlgorithm, key)
	}
	return &s, nil
}

// Public returns the public key for the signer.
func (s *Signer) Public() crypto.PublicKey {
	return s.pub
}

// Sets any sign/decrypt operation to always return an error.
// Returned error is always wrapped error cryptokms.ErrAsymmetricSign
// if its sign operation or cryptokms.ErrAsymmetricDecrypt if its decrypt operation.
func (s *Signer) WithAlwaysError() *Signer {
	s.serr = true
	return s
}

// HashFunc returns the default hash algorithm used for computing the digest.
// This ensures that signer also implements [crypto.SignerOptions].
func (s *Signer) HashFunc() crypto.Hash {
	return s.hash
}

// SignerOpts returns sane default [crypto.SignerOpts].
func (s *Signer) SignerOpts() crypto.SignerOpts {
	return s.hash
}

// Default decrypter options.
func (s *Signer) DecrypterOpts() crypto.DecrypterOpts {
	return &rsa.OAEPOptions{
		Hash: s.hash,
	}
}

// CreatedAt always returns known timestamp.
func (s *Signer) CreatedAt() time.Time {
	return knownTS
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

// Sign is a wrapper around SignContext.
func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.SignContext(s.context(), rand, digest, opts)
}

// SignContext signs the given digest with asymmetric key.
// The random parameter is ignored, and thus it can be as nil.
func (s *Signer) SignContext(ctx context.Context, random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if err := context.Cause(ctx); err != nil {
		return nil, fmt.Errorf("%w: fakekms: %w", cryptokms.ErrAsymmetricSign, err)
	}

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
