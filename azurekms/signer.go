package azurekms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
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

// Signer implements [crypto.Signer] interface backed by Azure Key Vault Key.
type Signer struct {
	kid    *azkeys.ID
	ctx    context.Context
	mu     sync.RWMutex
	pub    crypto.PublicKey
	ctime  time.Time
	vtime  time.Time
	hash   crypto.Hash
	hmap   map[crypto.Hash]azkeys.JSONWebKeySignatureAlgorithm
	client *azkeys.Client
}

// Returns a new signer backed by Azure Key Vault Key.
func NewSigner(ctx context.Context, client *azkeys.Client, keyID azkeys.ID) (*Signer, error) {
	if client == nil {
		return nil, cryptokms.ErrInvalidKMSClient
	}

	keyInfo, err := client.GetKey(ctx, keyID.Name(), keyID.Version(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: azurekms: failed to get key(%s): %w", cryptokms.ErrGetKeyMetadata, keyID, err)
	}

	if *keyInfo.KeyBundle.Attributes.Enabled {
		return nil, fmt.Errorf("%w: azurekms: key(%s) is not enabled", cryptokms.ErrUnusableKeyState, keyID)
	}

	// Azure keys can be marked as not before
	// so check if its is marked as such, and if its is valid at time of signer construction.
	if keyInfo.KeyBundle.Attributes.NotBefore.After(time.Now()) {
		return nil, fmt.Errorf("%w: azurekms: key(%s) is not valid yet(%s)",
			cryptokms.ErrUnusableKeyState, keyID, keyInfo.KeyBundle.Attributes.NotBefore.String())
	}

	// Build signer.
	signer := Signer{
		kid:    keyInfo.Key.KID,
		client: client,
		ctime:  *keyInfo.Attributes.Created,
		hmap:   make(map[crypto.Hash]azkeys.JSONWebKeySignatureAlgorithm),
	}

	if keyInfo.Attributes.Expires != nil {
		signer.vtime = *keyInfo.Attributes.Expires
	}

	// Check key type
	switch *keyInfo.Key.Kty {
	case azkeys.JSONWebKeyTypeEC, azkeys.JSONWebKeyTypeECHSM:
		pub := ecdsa.PublicKey{
			X: new(big.Int).SetBytes(keyInfo.Key.X),
			Y: new(big.Int).SetBytes(keyInfo.Key.Y),
		}

		switch *keyInfo.Key.Crv {
		case azkeys.JSONWebKeyCurveNameP256:
			signer.hmap[crypto.SHA256] = azkeys.JSONWebKeySignatureAlgorithmES256
			pub.Curve = elliptic.P256()
			signer.hash = crypto.SHA256
		case azkeys.JSONWebKeyCurveNameP384:
			signer.hmap[crypto.SHA384] = azkeys.JSONWebKeySignatureAlgorithmES384
			pub.Curve = elliptic.P384()
			signer.hash = crypto.SHA384
		case azkeys.JSONWebKeyCurveNameP521:
			signer.hmap[crypto.SHA512] = azkeys.JSONWebKeySignatureAlgorithmES512
			pub.Curve = elliptic.P521()
			signer.hash = crypto.SHA512
		case azkeys.JSONWebKeyCurveNameP256K:
			return nil, fmt.Errorf("%w: azurekms: P-256K key(%s) is not supported",
				cryptokms.ErrKeyAlgorithm, keyID)
		default:
			return nil, fmt.Errorf("%w: azurekms: unknown EC curve(%s) for key %s",
				cryptokms.ErrKeyAlgorithm, *keyInfo.Key.Crv, keyID)
		}

		signer.pub = &pub
	case azkeys.JSONWebKeyTypeRSA, azkeys.JSONWebKeyTypeRSAHSM:
		pub := rsa.PublicKey{
			N: new(big.Int).SetBytes(keyInfo.Key.N),
			E: int(new(big.Int).SetBytes(keyInfo.Key.E).Int64()),
		}

		signer.hmap[crypto.SHA256] = azkeys.JSONWebKeySignatureAlgorithmRS256
		signer.hmap[crypto.SHA384] = azkeys.JSONWebKeySignatureAlgorithmRS384
		signer.hmap[crypto.SHA512] = azkeys.JSONWebKeySignatureAlgorithmRS512

		signer.hash = crypto.SHA256
		signer.pub = &pub
	case azkeys.JSONWebKeyTypeOct, azkeys.JSONWebKeyTypeOctHSM:
		return nil, fmt.Errorf("%w: azurekms: symmetric key(%s) cannot be used for signing",
			cryptokms.ErrKeyAlgorithm, keyID)
	default:
		return nil, fmt.Errorf("%w: azurekms: unknown key type(%s) for key %s",
			cryptokms.ErrKeyAlgorithm, *keyInfo.Key.Kty, keyID)
	}

	return &signer, nil
}

// Public returns the public key for the signer.
func (s *Signer) Public() crypto.PublicKey {
	return s.pub
}

// HashFunc returns the default hash algorithm used for computing the digest.
// If underlying KMS key supports multiple hashes, defaults to best suitable hash.
// In most AWSKMS cases when multiple signing algorithms are supported, this
// is [crypto.SHA256].
func (s *Signer) HashFunc() crypto.Hash {
	return s.hash
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
//
// Deprecated: Use SignContext instead.
func (s *Signer) WithContext(ctx context.Context) *Signer {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ctx = ctx
	return s
}

// Sign is a wrapper around SignContext.
//
// Deprecated: Use SignContext instead.
func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.SignContext(s.context(), rand, digest, opts)
}

// SignContext signs the given digest with asymmetric key.
func (s *Signer) SignContext(ctx context.Context, _ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.client == nil || s.kid == nil || s.pub == nil {
		return nil, cryptokms.ErrInvalidKMSClient
	}

	// When no options are specified, use default hashing algorithm.
	// and when specified, ensure specified digest matches the options.
	if opts == nil {
		opts = s.HashFunc()
	}

	// Check if given hash function is supported by KMS key
	// If unsupported hash function is given, return a helpful message.
	algo, ok := s.hmap[opts.HashFunc()]
	if !ok {
		return nil, fmt.Errorf("%w: azurekms: hash(%s) is not supported by key(%s), use(%s) instead",
			cryptokms.ErrDigestAlgorithm, opts.HashFunc().String(), *s.kid, s.hash.String())
	}

	if len(digest) != opts.HashFunc().Size() {
		return nil, fmt.Errorf("%w: length is %d, want %d",
			cryptokms.ErrDigestLength, len(digest), opts.HashFunc().Size())
	}

	signResp, err := s.client.Sign(
		ctx, s.kid.Name(),
		s.kid.Version(),
		azkeys.SignParameters{
			Algorithm: &algo,
			Value:     digest,
		},
		nil,
	)

	if err != nil {
		return nil, fmt.Errorf("%w: azurekms: failed to sign with %s(version=%s): %w",
			cryptokms.ErrAsymmetricSign, s.kid.Name(), s.kid.Version(), err)
	}

	return signResp.Result, nil
}
