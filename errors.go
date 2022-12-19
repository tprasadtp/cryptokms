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
	// ErrInvalidInput is returned when input to verifier/encrypt is invalid or nil.
	ErrInvalidInput = Error("cryptokms: input is invalid, nil or empty")

	// Unknown or unsupported ley algorithm. This can be because either key algorithm
	// is unsupported by this library or the KMS backend does not support specified
	// crypto operation due to key usage restrictions or limitations.
	// Typically occurs when wrong key is of wrong type/purpose.
	ErrKeyAlgorithm = Error("cryptokms: unknown or unsupported key algorithm")

	// ErrDigestAlgorithmMismatch is returned when specified hash algorithm is
	// incompatible with KMS key or is not supported.
	ErrDigestAlgorithm = Error("cryptokms: digest algorithm cannot be used with the key")

	// ErrDigestLength is returned when specified digest is of invalid length.
	ErrDigestLength = Error("cryptokms: digest length is invalid")
)
