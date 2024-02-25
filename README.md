<div align="center">

# Crypto Helpers for KMS backed keys

[![go-reference](https://img.shields.io/badge/godoc-reference-5272b4?logo=go&labelColor=3a3a3a&logoColor=959da5)](https://pkg.go.dev/github.com/tprasadtp/cryptokms)
[![go-version](https://img.shields.io/github/go-mod/go-version/tprasadtp/cryptokms?logo=go&labelColor=3a3a3a&logoColor=959da5&color=00add8&label=go)](https://github.com/tprasadtp/cryptokms/blob/master/go.mod)
[![test](https://github.com/tprasadtp/cryptokms/actions/workflows/test.yml/badge.svg)](https://github.com/tprasadtp/cryptokms/actions/workflows/test.yml)
[![lint](https://github.com/tprasadtp/cryptokms/actions/workflows/lint.yml/badge.svg)](https://github.com/tprasadtp/cryptokms/actions/workflows/lint.yml)
[![release](https://github.com/tprasadtp/cryptokms/actions/workflows/release.yml/badge.svg)](https://github.com/tprasadtp/cryptokms/actions/workflows/release.yml)
[![license](https://img.shields.io/github/license/tprasadtp/cryptokms?logo=github&labelColor=3a3a3a&logoColor=959da5)](https://github.com/tprasadtp/cryptokms/blob/master/LICENSE)
[![version](https://img.shields.io/github/v/tag/tprasadtp/cryptokms?label=version&sort=semver&logo=semver&labelColor=3a3a3a&logoColor=959da5&color=ce3262)](https://github.com/tprasadtp/cryptokms/releases)

</div>

Implements [crypto.Signer] and [crypto.Decrypter] for keys typically backed by KMS service.
Currently it supports keys backed by,

- [Google Cloud KMS]
- [AWS KMS]
- Filesystem
- From memory.

Dependencies are neatly isolated. If you pull gcpkms package only google cloud dependencies should be pulled. Code has extensive unit tests and integration tests.

Uses sensible and sane defaults.

- RSA keys of size less than 2048 are not supported.
- ECC Keys of size less than 256 are not supported.
- Signing algorithms with insecure hashes (SHA1, MD5 etc) are not supported.

## Google KMS (Signing Keys)

| Key Algorithm | Hash Algorithm | Supported Interfaces |
|---|---|---
| [`EC_SIGN_P256_SHA256`][gcp_ec](recommended) | [sha256] | [crypto.Signer], [crypto.SignerOpts]
| [`EC_SIGN_P384_SHA384`][gcp_ec] | [sha384] | [crypto.Signer], [crypto.SignerOpts]
| [`RSA_SIGN_PKCS1_2048_SHA256`][gcp_rsa] | [sha256] | [crypto.Signer], [crypto.SignerOpts]
| [`RSA_SIGN_PKCS1_3072_SHA256`][gcp_rsa] | [sha256] | [crypto.Signer], [crypto.SignerOpts]
| [`RSA_SIGN_PKCS1_4096_SHA256`][gcp_rsa] | [sha256] | [crypto.Signer], [crypto.SignerOpts]
| [`RSA_SIGN_PKCS1_4096_SHA512`][gcp_rsa] | [sha512] | [crypto.Signer], [crypto.SignerOpts]

> [!IMPORTANT]
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

> [!IMPORTANT]
>
> Use in-memory non swap-able file system (like ramfs) or from kubernetes secret store CSI.
> For systems using systemd, [systemd-credentials] can be used as keys can be encrypted,
> bound to TPM and are only present in memory. In other cases this may be insecure.

Keys on disk must be not encrypted with a passphrase. Private key in PKCS #8, ASN.1 DER form(`PRIVATE KEY`), RSA private key in PKCS #1, ASN.1 DER form(`RSA PRIVATE KEY`) and EC private key in SEC 1, ASN.1 DER form (`EC PRIVATE KEY`) are supported.

| Key Algorithm | Supported Hashes | Interfaces |
|---|---|---
| `RSA_2048` | [SHA1][sha1], [SHA256][sha256], [SHA512][sha512] | [crypto.Decrypter], [crypto.Signer]
| `RSA_3072` | [SHA1][sha1], [SHA256][sha256], [SHA512][sha512] | [crypto.Decrypter], [crypto.Signer]
| `RSA_4096` | [SHA1][sha1], [SHA256][sha256], [SHA512][sha512] | [crypto.Decrypter], [crypto.Signer]
| `ECC-P256` | [SHA256][sha256] | [crypto.Signer]
| `ECC-P384` | [SHA384][sha384] | [crypto.Signer]
| `ECC-P521` | [SHA512][sha512] | [crypto.Signer]
| `ED-25519` | [SHA512][sha512] (ed25519ph only) | [crypto.Signer]

## From memory

If keys are stored in memory or environment variables, use `memkms`. It is identical to
filekms except keys are in-process and are provided directly. Key must be PEM encoded.

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
[systemd-credentials]: https://www.freedesktop.org/software/systemd/man/systemd-creds.html
