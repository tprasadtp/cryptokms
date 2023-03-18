package cryptokms

// Compile time check to ensure [Error] implements error interface.
var _ error = (*Error)(nil)

// Error is a simple immutable sentinel error implementation.
//
// While exported errors are covered by semver compatibility,
// error strings themselves are not. Use [errors.Is] for checking
// errors. This is mainly due to fact that cloud provides
// rename products or product brands and can add new functionality.
type Error string

// Implements error interface.
func (e Error) Error() string {
	return string(e)
}

const (
	// KMS client specified is invalid or nil.
	ErrInvalidKMSClient = Error("cryptokms: KeyManagementClient is invalid or nil")

	// ErrInvalidInput is returned when input to verifier/encrypt is invalid or nil.
	ErrInvalidInput = Error("cryptokms: input is invalid, nil or empty")

	// Unknown or unsupported ley algorithm. This can be because either key algorithm
	// is unsupported by this library or the KMS backend does not support specified
	// crypto operation due to key usage restrictions or limitations.
	// Typically occurs when wrong key is of wrong type/purpose.
	ErrKeyAlgorithm = Error("cryptokms: unknown or unsupported key algorithm")

	// ErrAsymmetricSign is returned when AsymmetricSign operation fails.
	ErrAsymmetricSign = Error("cryptokms: failed to perform asymmetric sign")

	// ErrAsymmetricDecrypt is returned when AsymmetricDecrypt operation fails.
	ErrAsymmetricDecrypt = Error("cryptokms: failed to perform asymmetric decryption")

	// ErrDecrypterOpts is returned when decryption options are not supported by the
	// KMS key backend. This can happen for example if you try to decrypt
	// with [rsa.PKCS1v15DecryptOptions] when backed only supports [rsa.OAEPOptions].
	ErrDecrypterOpts = Error("cryptokms: unsupported decrypter options")

	// ErrPayloadTooLarge is returned when payload is too large.
	// Limits depend on the KMS provider, server/IAM configuration and key types.
	ErrPayloadTooLarge = Error("cryptokms: payload is too large")

	// ErrUnsupportedMethod is returned if RPC/API method or operation is not supported by the key.
	// For example using HMAC signing key for Asymmetric sign operations.
	ErrUnsupportedMethod = Error("cryptokms: method/op is not supported by this key")

	// ErrUnknownURI is returned if key URI format is unknown.
	ErrUnknownURI = Error("cryptokms: Key URI format is unknown")

	// ErrDigestAlgorithmMismatch is returned when specified hash algorithm is
	// incompatible with KMS key or is not supported.
	ErrDigestAlgorithm = Error("cryptokms: digest algorithm cannot be used with the key")

	// ErrDigestLength is returned when specified digest is of invalid length.
	ErrDigestLength = Error("cryptokms: digest length is invalid")

	// ErrUnusableKeyState is returned when key is in unusable state.
	// This can be because key is disabled, scheduled to be destroyed
	// or key material is already destroyed.
	ErrUnusableKeyState = Error("cryptokms: key is in unusable state")

	// ErrGetKeyMetadata is returned when fetching or parsing key metadata fails.
	// Most likely reason being IAM/Permission issues.
	// Please ensure that caller has permissions to "describe" and "get public key" operations.
	ErrGetKeyMetadata = Error("cryptokms: failed to fetch key metadata")
)
