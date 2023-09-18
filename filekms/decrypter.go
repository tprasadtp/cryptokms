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

var (
	_ cryptokms.Decrypter = (*Decrypter)(nil)
	_ crypto.Decrypter    = (*Decrypter)(nil)
)

// Decrypter.
type Decrypter struct {
	ctx              context.Context
	hash             crypto.Hash
	pub              crypto.PublicKey
	decrypter        *rsa.PrivateKey
	maxCiphertextLen int
	ts               time.Time
	mu               sync.RWMutex
	algo             cryptokms.Algorithm
}

// NewDecrypter returns a new decrypter based on key in the path specified.
func NewDecrypter(path string) (*Decrypter, error) {
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

	decrypter := &Decrypter{
		ts: fileInfo.ModTime(),
	}

	switch v := priv.(type) {
	case *rsa.PrivateKey:
		decrypter.pub = v.Public()
		decrypter.decrypter = v
		switch v.N.BitLen() {
		case 2048:
			decrypter.hash = crypto.SHA256
			decrypter.algo = cryptokms.AlgorithmRSA2048
			decrypter.maxCiphertextLen = 2048 / 8
		case 3072:
			decrypter.hash = crypto.SHA256
			decrypter.algo = cryptokms.AlgorithmRSA3072
			decrypter.maxCiphertextLen = 3072 / 8
		case 4096:
			decrypter.hash = crypto.SHA256
			decrypter.algo = cryptokms.AlgorithmRSA4096
			decrypter.maxCiphertextLen = 4096 / 8
		default:
			return nil, fmt.Errorf("filekms: RSA key len(%d) is not supported: %w",
				v.N.BitLen(), cryptokms.ErrKeyAlgorithm)
		}
	case *ecdsa.PrivateKey:
		return nil, fmt.Errorf("%w: filekms: ECDSA key is not supported for decryption", cryptokms.ErrKeyAlgorithm)
	case ed25519.PrivateKey, *ed25519.PrivateKey:
		return nil, fmt.Errorf("%w: filekms: ed25519 key is not supported for decryption", cryptokms.ErrKeyAlgorithm)
	default:
		return nil, fmt.Errorf("%w: unknown key type: %T", cryptokms.ErrKeyAlgorithm, v)
	}

	return decrypter, nil
}

// Public returns the public key for the [Decrypter].
func (d *Decrypter) Public() crypto.PublicKey {
	return d.pub
}

// CreatedAt returns time at which the key file was last modified.
func (d *Decrypter) CreatedAt() time.Time {
	return d.ts
}

// HashFunc returns the hash algorithm used for computing the digest.
func (d *Decrypter) HashFunc() crypto.Hash {
	return d.hash
}

// SignerOpts returns a default decrypter option.
func (d *Decrypter) DecrypterOpts() crypto.DecrypterOpts {
	return &rsa.OAEPOptions{
		Hash: d.hash,
	}
}

// Algorithm returns key algorithm.
func (d *Decrypter) Algorithm() cryptokms.Algorithm {
	return d.algo
}

// context returns the context for this signer or
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

// WithContext adds the given context to the signer.
func (d *Decrypter) WithContext(ctx context.Context) *Decrypter {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.ctx = ctx
	return d
}

// Sign is a wrapper around SignContext.
func (d *Decrypter) Decrypt(_ io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return d.DecryptContext(d.context(), nil, ciphertext, opts)
}

// DecryptContext decrypts the message with asymmetric key.
// The rand parameter is ignored, and it can be nil.
func (d *Decrypter) DecryptContext(ctx context.Context, _ io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if err := context.Cause(ctx); err != nil {
		return nil, fmt.Errorf("%w: fakekms: %w", cryptokms.ErrAsymmetricDecrypt, err)
	}

	if opts == nil {
		opts = d.DecrypterOpts()
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
		return nil, fmt.Errorf("%w: unknown decrypter options type %T", cryptokms.ErrDecrypterOpts, opts)
	}

	if len(ciphertext) > d.maxCiphertextLen {
		return nil, fmt.Errorf("%w: ciphertext cannot be larger than %d bytes",
			cryptokms.ErrPayloadTooLarge, d.maxCiphertextLen)
	}

	plaintext, err := d.decrypter.Decrypt(rand.Reader, ciphertext, opts)

	if err != nil {
		return nil, fmt.Errorf("%w: fakekms: failed to decrypt: %w",
			cryptokms.ErrAsymmetricDecrypt, err)
	}

	return plaintext, nil
}
