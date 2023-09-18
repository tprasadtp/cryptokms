package filekms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tprasadtp/cryptokms"
)

// Compile time check to ensure [Signer] implements
// [github.com/tprasadtp/cryptokms.Signer], [crypto.Signer]
// [github.com/tprasadtp/cryptokms.Decrypter],
// and [crypto.SignerOpts].
var (
	_ cryptokms.Signer  = (*Signer)(nil)
	_ crypto.Signer     = (*Signer)(nil)
	_ crypto.SignerOpts = (*Signer)(nil)
)

// Signer.
//
//nolint:nocontext // ignore
type Signer struct {
	ctx    context.Context
	hash   crypto.Hash
	pub    crypto.PublicKey
	signer crypto.Signer
	ts     time.Time
	mu     sync.RWMutex
	algo   cryptokms.Algorithm
}

// NewSigner returns a new signer based on key in the path specified.
func NewSigner(path string) (*Signer, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("filekms: failed to detect abs path: %w", err)
	}

	fileInfo, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("filekms: failed to stat file: %w", err)
	}

	if !fileInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("filekms: file is not a regular file: %s",
			fileInfo.Mode())
	}

	if fileInfo.Size() > 10000 {
		return nil, fmt.Errorf("filekms: file size is larger than 10kB(%dB)",
			fileInfo.Size())
	}

	file, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("filekms: failed to open file: %w", err)
	}

	slurp, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("filekms: failed to read from file: %w", err)
	}

	block, _ := pem.Decode(slurp)
	if block == nil {
		return nil, fmt.Errorf("filekms: key must be PEM encoded")
	}

	// Try to parse key as private key.
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf(
			"filekms: cannot parse PEM encoded bytes as private key: %w", err)
	}

	signer := &Signer{
		ts: fileInfo.ModTime(),
	}

	switch v := priv.(type) {
	case *rsa.PrivateKey:
		signer.pub = v.Public()
		signer.signer = v
		switch v.N.BitLen() {
		case 2048:
			signer.hash = crypto.SHA256
			signer.algo = cryptokms.AlgorithmRSA2048
		case 3072:
			signer.hash = crypto.SHA256
			signer.algo = cryptokms.AlgorithmRSA3072
		case 4096:
			signer.hash = crypto.SHA256
			signer.algo = cryptokms.AlgorithmRSA4096
		default:
			return nil, fmt.Errorf("filekms: RSA key len(%d) is not supported: %w",
				v.N.BitLen(), cryptokms.ErrKeyAlgorithm)
		}
	case *ecdsa.PrivateKey:
		signer.pub = v.Public()
		signer.signer = v
		switch v.Params().BitSize {
		case 256:
			signer.hash = crypto.SHA256
			signer.algo = cryptokms.AlgorithmECP256
		case 384:
			signer.hash = crypto.SHA384
			signer.algo = cryptokms.AlgorithmECP384
		case 521:
			signer.hash = crypto.SHA512
			signer.algo = cryptokms.AlgorithmECP521
		}
	case ed25519.PrivateKey:
		signer.pub = v.Public()
		signer.signer = v
		signer.algo = cryptokms.AlgorithmED25519
		signer.hash = crypto.SHA512
	default:
		return nil, fmt.Errorf("%w: unknown key type: %T", cryptokms.ErrKeyAlgorithm, v)
	}

	return signer, nil
}

// Public returns the public key for the [Signer].
func (s *Signer) Public() crypto.PublicKey {
	return s.pub
}

// CreatedAt returns time at which the key file was last modified.
func (s *Signer) CreatedAt() time.Time {
	return s.ts
}

// HashFunc returns the hash algorithm used for computing the digest.
func (s *Signer) HashFunc() crypto.Hash {
	return s.hash
}

// SignerOpts Returns a valid signer option suitable for using with Sign.
func (s *Signer) SignerOpts() crypto.SignerOpts {
	return s.hash
}

// Algorithm returns key algorithm.
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
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.SignContext(s.context(), nil, digest, opts)
}

// SignContext signs the given digest with asymmetric key.
// The random parameter is ignored, and thus it can be as nil and is always set to
// [crypto/rand.Reader].
//
//nolint:gocognit // ignore
func (s *Signer) SignContext(ctx context.Context, _ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if err := context.Cause(ctx); err != nil {
		return nil, fmt.Errorf("%w: filekms: %w", cryptokms.ErrAsymmetricSign, err)
	}

	if opts == nil {
		opts = s.hash
	}

	switch v := s.signer.(type) {
	case *rsa.PrivateKey:
		pss, ok := opts.(*rsa.PSSOptions)
		if ok {
			// Fallback to default secure hash.
			if pss.Hash == 0 {
				pss.Hash = s.hash
			}

			// Typically salt length of 0 is accepted but results
			// in deterministic hash, assuming pss is used to avoid deterministic outputs.
			if pss.SaltLength == 0 {
				pss.SaltLength = pss.Hash.Size()
			}

			// Most KMS provides restrict or do not allow changing salt length.
			// So, restrict to file as well.
			if pss.SaltLength != pss.Hash.Size() {
				return nil, fmt.Errorf(
					"%w: filekms: salt length(%d) must be same as digest length(%d)",
					cryptokms.ErrSignerOpts, pss.SaltLength, pss.Hash.Size())
			}
		}

		if len(digest) != opts.HashFunc().Size() {
			return nil, fmt.Errorf("%w: fakekms: digest length is %d, want %d",
				cryptokms.ErrDigestLength, len(digest), opts.HashFunc().Size())
		}
	case *ecdsa.PrivateKey:
		switch ov := opts.(type) {
		case *crypto.Hash, crypto.Hash:
		default:
			return nil, fmt.Errorf("%w: filekms: ECDSA unsupported signer options: %T",
				cryptokms.ErrSignerOpts, ov)
		}

		switch s.algo {
		case cryptokms.AlgorithmECP256:
			if opts.HashFunc().HashFunc() != crypto.SHA256 {
				return nil, fmt.Errorf("%w: filekms: ECDSA-P256 key only supports hash algorithm %s",
					cryptokms.ErrDigestAlgorithm, crypto.SHA256)
			}
		case cryptokms.AlgorithmECP384:
			if opts.HashFunc() != crypto.SHA384 {
				return nil, fmt.Errorf("%w: filekms: ECDSA-P384 key only supports hash algorithm %s",
					cryptokms.ErrDigestAlgorithm, crypto.SHA384)
			}
		case cryptokms.AlgorithmECP521:
			if opts.HashFunc() != crypto.SHA512 {
				return nil, fmt.Errorf("%w: filekms: ECDSA-P521 key only supports hash algorithm %s",
					cryptokms.ErrDigestAlgorithm, crypto.SHA512)
			}
		default:
			panic(fmt.Sprintf("filekms: unknown ECDSA algorithm: %s", s.algo))
		}
	case ed25519.PrivateKey, *ed25519.PrivateKey:
		switch ov := opts.(type) {
		case *crypto.Hash, crypto.Hash:
		default:
			return nil, fmt.Errorf("%w: filekms: ED25519 unsupported signer options: %T",
				cryptokms.ErrSignerOpts, ov)
		}

		if opts.HashFunc() != crypto.SHA512 {
			return nil, fmt.Errorf("%w: filekms: ED25519 unsupported signer options: %s",
				cryptokms.ErrDigestAlgorithm, opts.HashFunc())
		}
	default:
		return nil, fmt.Errorf("%w: filekms: unknown key type: %T", cryptokms.ErrKeyAlgorithm, v)
	}

	// Ensure digest length is valid.
	if len(digest) != opts.HashFunc().Size() {
		return nil, fmt.Errorf("%w: filekms: length is %d, want %d",
			cryptokms.ErrDigestLength, len(digest), s.hash.Size())
	}

	// Perform signing operation.
	signature, err := s.signer.Sign(rand.Reader, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("%w: filekms: failed to sign: %w",
			cryptokms.ErrAsymmetricSign, err)
	}
	return signature, nil
}
