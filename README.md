# Crypto Helpers for KMS backed keys

[![Go Reference](https://pkg.go.dev/badge/github.com/tprasadtp/cryptokmssvg)](https://pkg.go.dev/github.com/tprasadtp/cryptokms)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/tprasadtp/cryptokms?label=go&logo=go&logoColor=white)
[![test](https://github.com/tprasadtp/cryptokms/actions/workflows/test.yml/badge.svg)](https://github.com/tprasadtp/cryptokms/actions/workflows/test.yml)
![GitHub](https://img.shields.io/github/license/tprasadtp/cryptokms)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/tprasadtp/cryptokms?color=7f50a6&label=release&logo=semver&sort=semver)

Implements [crypto.Signer] and [crypto.Decrypter] for keys typically backed by KMS service.
Currently it supports keys backed by,

- [Google Cloud KMS]
- [AWS KMS]
- Filesystem
- Test keys generated per run for testing.

Dependencies are neatly isolated. If you pull gcpkms package only google cloud dependencies should be pulled. Code has extensive unit tests and integration tests.

Uses sensible and sane defaults.

- RSA keys of size less than 2048 are not supported.
- ECC Keys of size less than 256 are not supported.
- Signing algorithms with insecure hashes (SHA1, MD5) are not supported.

## Google KMS (Signing Keys)

| Key Algorithm | Hash Algorithm | Supported Interfaces |
|---|---|---
| [`EC_SIGN_P256_SHA256`][gcp_ec](recommended) | [sha256] | [crypto.Signer], [crypto.SignerOpts]
| [`EC_SIGN_P384_SHA384`][gcp_ec] | [sha384] | [crypto.Signer], [crypto.SignerOpts]
| [`RSA_SIGN_PKCS1_2048_SHA256`][gcp_rsa] | [sha256] | [crypto.Signer], [crypto.SignerOpts]
| [`RSA_SIGN_PKCS1_3072_SHA256`][gcp_rsa] | [sha256] | [crypto.Signer], [crypto.SignerOpts]
| [`RSA_SIGN_PKCS1_4096_SHA256`][gcp_rsa] | [sha256] | [crypto.Signer], [crypto.SignerOpts]
| [`RSA_SIGN_PKCS1_4096_SHA512`][gcp_rsa] | [sha512] | [crypto.Signer], [crypto.SignerOpts]

> **Note**
>
> `RSA_SIGN_PSS_*`, `RSA_SIGN_RAW_*` and external KMS keys are **not** supported.

## Google KMS (Encryption Keys)

| Key Algorithm | Hash Algorithm | Supported Interfaces |
|---|---|---
| [`RSA_DECRYPT_OAEP_2048_SHA1`][gcp_decrypt] | [sha1] | [crypto.Decrypter]
| [`RSA_DECRYPT_OAEP_3072_SHA1`][gcp_decrypt] | [sha1] | [crypto.Decrypter]
| [`RSA_DECRYPT_OAEP_4096_SHA1`][gcp_decrypt] | [sha1] | [crypto.Decrypter]
| [`RSA_DECRYPT_OAEP_2048_SHA256`][gcp_decrypt] | [sha256] | [crypto.Decrypter]
| [`RSA_DECRYPT_OAEP_3072_SHA256`][gcp_decrypt](recommended) | [sha256] | [crypto.Decrypter]
| [`RSA_DECRYPT_OAEP_4096_SHA256`][gcp_decrypt] | [sha256] | [crypto.Decrypter]
| [`RSA_DECRYPT_OAEP_4096_SHA512`][gcp_decrypt] | [sha512] | [crypto.Decrypter]


## AWS KMS (Signing Keys)

| Key Algorithm | Key Usage | Hash Algorithm | Supported Interfaces |
|---|---|---|---
| [`RSA_2048`][awskms_keyspec] | `SIGN_VERIFY` | [sha256], [sha384], [sha512] | [crypto.Signer], [crypto.SignerOpts]
| [`RSA_3072`][awskms_keyspec] | `SIGN_VERIFY` | [sha256], [sha384], [sha512] | [crypto.Signer], [crypto.SignerOpts]
| [`RSA_4096`][awskms_keyspec] | `SIGN_VERIFY`| [sha256], [sha384], [sha512] | [crypto.Signer], [crypto.SignerOpts]
| [`ECC_NIST_P256`][awskms_keyspec](recommended) | `SIGN_VERIFY` | [sha256] | [crypto.Signer], [crypto.SignerOpts]
| [`ECC_NIST_384`][awskms_keyspec] | `SIGN_VERIFY` | [sha384] | [crypto.Signer], [crypto.SignerOpts]
| [`ECC_NIST_P521`][awskms_keyspec] | `SIGN_VERIFY` | [sha512] | [crypto.Signer], [crypto.SignerOpts]


## AWS KMS (Encryption Keys)

| Key Algorithm | Key Usage | Encryption Algorithms | Supported Interfaces |
|---|---|---|---
| [`RSA_2048`][awskms_keyspec] | `ENCRYPT_DECRYPT` | `RSAES_OAEP_SHA_1`,`RSAES_OAEP_SHA_256` | [crypto.Decrypter]
| [`RSA_3072`][awskms_keyspec] | `ENCRYPT_DECRYPT` | `RSAES_OAEP_SHA_1`,`RSAES_OAEP_SHA_256` | [crypto.Decrypter]
| [`RSA_4096`][awskms_keyspec] | `ENCRYPT_DECRYPT` | `RSAES_OAEP_SHA_1`,`RSAES_OAEP_SHA_256` | [crypto.Decrypter]


## Keys from filesystem

> **Warning**
>
> Use in-memory non swappable file system (like ramfs).
> This can be used together with systemd-credentials(8) as keys can be encrypted,
> bound to TPM and are only present in memory. In other cases this is insecure.

- Keys on disk must be not encrypted with a passphrase and in PEM encoded PKCS8 format.

| Key Algorithm | Supported Algorithm | Interfaces |
|---|---|---
| `RSA_2048` | [crypto.Decrypter], [crypto.Signer]
| `RSA_3072` | [crypto.Decrypter], [crypto.Signer]
| `RSA_4096` | [crypto.Decrypter], [crypto.Signer]
| `ECC-P256` | [crypto.Signer]
| `ECC-P384` | [crypto.Signer]
| `ECC-P521` | [crypto.Signer]
| `ED-25519` | [crypto.Signer]


## Fake KMS

Library also provides a fake KMS provider backed by _ephemeral in-memory keys_ **ONLY** for test usage.
**DO NOT** use them for in non-test code. Keys are generated on demand and are used during the
lifecycle of the binary.

[Google Cloud KMS]: https://cloud.google.com/kms/docs
[AWS KMS]: https://aws.amazon.com/kms/

[gcp_rsa]: https://cloud.google.com/kms/docs/algorithms#rsa_signing_algorithms
[gcp_decrypt]: https://cloud.google.com/kms/docs/algorithms#asymmetric_encryption_algorithms
[gcp_ec]: https://cloud.google.com/kms/docs/algorithms#elliptic_curve_signing_algorithms

[awskms_keyspec]: https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html

[sha1]: https://pkg.go.dev/crypto/sha1
[sha256]: https://pkg.go.dev/crypto/sha256
[sha512]: https://pkg.go.dev/crypto/sha512
[sha384]: https://pkg.go.dev/crypto/sha384
[crypto.Signer]: https://pkg.go.dev/crypto#Signer
[crypto.SignerOpts]: https://pkg.go.dev/crypto#SignerOpts
[crypto.Decrypter]: https://pkg.go.dev/crypto#Decrypter
