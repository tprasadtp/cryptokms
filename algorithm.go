package cryptokms

// Key algorithm rype.
//
//go:generate stringer -type Algorithm -trimprefix=Algorithm
type Algorithm int

const (
	AlgorithmUnknown Algorithm = iota
	// RSA asymmetric algorithms.
	AlgorithmRSA2048
	AlgorithmRSA3072
	AlgorithmRSA4096
	AlgorithmRSA8192

	// NIST P-256 elliptic curve key algorithms.
	AlgorithmECP256
	// NIST P-384 elliptic curve key algorithms.
	AlgorithmECP384
	// NIST P-521 elliptic curve key algorithms.
	AlgorithmECP521

	// ED-25519.
	AlgorithmED25519

	// AWS symmetric key algorithm.
	AlgorithmSymmetricAWS
	// GCP symmetric key algorithm.
	AlgorithmSymmetricGCP
)
