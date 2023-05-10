package cryptokms

//go:generate stringer -type Backend -trimprefix=Backend

// KMS Backend Type.
type Backend int

const (
	// Keys are backed by Google Cloud KMS.
	BackendGoogleCloudKMS Backend = iota + 1
	// Keys are backed by AWS KMS.
	BackendAWSKMS
	// Keys are backed by Hashicorp Vault Transit backed.
	BackendHashicorpVault
	// Keys are backed by Azure Key Vault Keys.
	BackendAzureKeyVault
	// On-the fly generated keys unique per binary session
	// backed by in process memory.
	// Use only for unit and integration testing.
	BackendFakeKMS
	// Filesystem. This is insecure as private key material
	// may reside on non-encrypted filesystem.
	BackendFilesystem
	// Keys are backed by TPM 2. TPM 1.2 is unsupported.
	BackendTPM
)
