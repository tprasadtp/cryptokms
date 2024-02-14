// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package gcpkms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/tprasadtp/cryptokms/internal/shared"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// wellknown timestamp for use in tests.
var knownTS = time.Unix(1136239445, 0)

// Fake KMS service implementation.
type fakeService struct {
	kmspb.UnimplementedKeyManagementServiceServer
}

// Implement GetCryptoKeyVersionRequest.
// Key name determines response.
//   - keys starting with DISABLED_ are always in DESTROYED state.
//   - keys containing string ERROR_GET_CRYPTOKEY_VERSION will return an error.
func (svc *fakeService) GetCryptoKeyVersion(_ context.Context, req *kmspb.GetCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	// Build a fake response.
	resp := &kmspb.CryptoKeyVersion{
		Name:            req.Name,
		ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
		GenerateTime:    timestamppb.New(knownTS),
		CreateTime:      timestamppb.New(knownTS),
	}

	if strings.Contains(req.Name, "DESTROYED") {
		resp.State = kmspb.CryptoKeyVersion_DESTROYED
		resp.DestroyEventTime = timestamppb.Now()
		resp.DestroyTime = timestamppb.Now()
	} else {
		resp.State = kmspb.CryptoKeyVersion_ENABLED
	}

	// If key set to error, return an GRPC error response.
	if strings.Contains(req.Name, "ERROR_GET_CRYPTOKEY_VERSION") {
		return nil, status.Error(codes.Internal, "fake service error")
	}

	switch {
	// RSA PKCS1
	case strings.Contains(req.Name, "RSA_SIGN_PKCS1_2048_SHA256"):
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256
	case strings.Contains(req.Name, "RSA_SIGN_PKCS1_3072_SHA256"):
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256
	case strings.Contains(req.Name, "RSA_SIGN_PKCS1_4096_SHA256"):
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256
	case strings.Contains(req.Name, "RSA_SIGN_PKCS1_4096_SHA512"):
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512
	// PSS
	case strings.Contains(req.Name, "RSA_SIGN_PSS_2048_SHA256"):
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256
	case strings.Contains(req.Name, "RSA_SIGN_PSS_3072_SHA256"):
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256
	case strings.Contains(req.Name, "RSA_SIGN_PSS_4096_SHA256"):
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256
	case strings.Contains(req.Name, "RSA_SIGN_PSS_4096_SHA512"):
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512
	// EC Keys
	case strings.Contains(req.Name, "EC_SIGN_P256_SHA256"):
		resp.Algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
	case strings.Contains(req.Name, "EC_SIGN_P384_SHA384"):
		resp.Algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384
	case strings.Contains(req.Name, "EC_SIGN_SECP256K1_SHA256"):
		resp.Algorithm = kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256
	// Symmetric Keys
	case strings.Contains(req.Name, "GOOGLE_SYMMETRIC_ENCRYPTION"):
		resp.Algorithm = kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION
	// Encryption keys
	case strings.Contains(req.Name, "RSA_DECRYPT_OAEP_2048_SHA1"):
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA1
	case strings.Contains(req.Name, "RSA_DECRYPT_OAEP_2048_SHA256"):
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256
	case strings.Contains(req.Name, "RSA_DECRYPT_OAEP_3072_SHA1"):
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA1
	case strings.Contains(req.Name, "RSA_DECRYPT_OAEP_3072_SHA256"):
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256
	case strings.Contains(req.Name, "RSA_DECRYPT_OAEP_4096_SHA1"):
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA1
	case strings.Contains(req.Name, "RSA_DECRYPT_OAEP_4096_SHA256"):
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256
	case strings.Contains(req.Name, "RSA_DECRYPT_OAEP_4096_SHA512"):
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA512
	// HMAC Keys
	case strings.Contains(req.Name, "HMAC_SHA1"):
		resp.Algorithm = kmspb.CryptoKeyVersion_HMAC_SHA1
	case strings.Contains(req.Name, "HMAC_SHA224"):
		resp.Algorithm = kmspb.CryptoKeyVersion_HMAC_SHA224
	case strings.Contains(req.Name, "HMAC_SHA256"):
		resp.Algorithm = kmspb.CryptoKeyVersion_HMAC_SHA256
	case strings.Contains(req.Name, "HMAC_SHA384"):
		resp.Algorithm = kmspb.CryptoKeyVersion_HMAC_SHA384
	case strings.Contains(req.Name, "HMAC_SHA512"):
		resp.Algorithm = kmspb.CryptoKeyVersion_HMAC_SHA512
	case strings.Contains(req.Name, "EXTERNAL_SYMMETRIC_ENCRYPTION"):
		resp.Algorithm = kmspb.CryptoKeyVersion_EXTERNAL_SYMMETRIC_ENCRYPTION
	default:
		resp.Algorithm = kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED
		resp.State = kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_STATE_UNSPECIFIED
	}
	return resp, nil
}

// Returns public key.
//
//   - If key name contains ERROR_ON_GET_PUBLICKEY returns an error.
//   - If key name contains with ERROR_RESP_INTEGRITY returned response does not match checksum.
func (svc *fakeService) GetPublicKey(_ context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
	// If key set to force error, return an GRPC error response.
	if strings.Contains(req.Name, "ERROR_ON_GET_PUBLICKEY") {
		return nil, status.Error(codes.Internal, "fake service error")
	}

	resp := &kmspb.PublicKey{
		Name:            req.Name,
		ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
	}

	switch {
	// RSA PKCS1
	case strings.Contains(req.Name, "RSA_SIGN_PKCS1_2048_SHA256"):
		resp.Pem = string(shared.MustMarshalPublicKey(testkeys.GetRSA2048PublicKey()))
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256
	case strings.Contains(req.Name, "RSA_SIGN_PKCS1_3072_SHA256"):
		resp.Pem = string(shared.MustMarshalPublicKey(testkeys.GetRSA3072PublicKey()))
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256
	case strings.Contains(req.Name, "RSA_SIGN_PKCS1_4096_SHA256"):
		resp.Pem = string(shared.MustMarshalPublicKey(testkeys.GetRSA4096PublicKey()))
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256
	case strings.Contains(req.Name, "RSA_SIGN_PKCS1_4096_SHA512"):
		resp.Pem = string(shared.MustMarshalPublicKey(testkeys.GetRSA4096PublicKey()))
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512
	// PSS
	case strings.Contains(req.Name, "RSA_SIGN_PSS_2048_SHA256"):
		resp.Pem = string(shared.MustMarshalPublicKey(testkeys.GetRSA2048PublicKey()))
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256
	case strings.Contains(req.Name, "RSA_SIGN_PSS_3072_SHA256"):
		resp.Pem = string(shared.MustMarshalPublicKey(testkeys.GetRSA3072PublicKey()))
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256
	case strings.Contains(req.Name, "RSA_SIGN_PSS_4096_SHA256"):
		resp.Pem = string(shared.MustMarshalPublicKey(testkeys.GetRSA4096PublicKey()))
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256
	case strings.Contains(req.Name, "RSA_SIGN_PSS_4096_SHA512"):
		resp.Pem = string(shared.MustMarshalPublicKey(testkeys.GetRSA4096PublicKey()))
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512
	// EC Keys
	case strings.Contains(req.Name, "EC_SIGN_P256_SHA256"):
		resp.Pem = string(shared.MustMarshalPublicKey(testkeys.GetECP256PublicKey()))
		resp.Algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
	case strings.Contains(req.Name, "EC_SIGN_P384_SHA384"):
		resp.Algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384
		resp.Pem = string(shared.MustMarshalPublicKey(testkeys.GetECP384PublicKey()))
	// Symmetric Keys
	case strings.Contains(req.Name, "GOOGLE_SYMMETRIC_ENCRYPTION"):
		resp.Algorithm = kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION
	// Encryption keys
	case strings.Contains(req.Name, "RSA_DECRYPT_OAEP_2048_SHA1"):
		resp.Pem = string(shared.MustMarshalPublicKey(testkeys.GetRSA2048PublicKey()))
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA1
	case strings.Contains(req.Name, "RSA_DECRYPT_OAEP_2048_SHA256"):
		resp.Pem = string(shared.MustMarshalPublicKey(testkeys.GetRSA2048PublicKey()))
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256
	case strings.Contains(req.Name, "RSA_DECRYPT_OAEP_3072_SHA1"):
		resp.Pem = string(shared.MustMarshalPublicKey(testkeys.GetRSA3072PublicKey()))
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA1
	case strings.Contains(req.Name, "RSA_DECRYPT_OAEP_3072_SHA256"):
		resp.Pem = string(shared.MustMarshalPublicKey(testkeys.GetRSA3072PublicKey()))
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256
	case strings.Contains(req.Name, "RSA_DECRYPT_OAEP_4096_SHA1"):
		resp.Pem = string(shared.MustMarshalPublicKey(testkeys.GetRSA4096PublicKey()))
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA1
	case strings.Contains(req.Name, "RSA_DECRYPT_OAEP_4096_SHA256"):
		resp.Pem = string(shared.MustMarshalPublicKey(testkeys.GetRSA4096PublicKey()))
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256
	case strings.Contains(req.Name, "RSA_DECRYPT_OAEP_4096_SHA512"):
		resp.Pem = string(shared.MustMarshalPublicKey(testkeys.GetRSA4096PublicKey()))
		resp.Algorithm = kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA512
	case strings.Contains(req.Name, "EC_SIGN_SECP256K1_SHA256"):
		return nil, fmt.Errorf(
			"gcpkms(fake-server): GetPublicKey : unsupported EC_SIGN_SECP256K1_SHA256 key %s",
			req.Name)
	default:
		return nil, fmt.Errorf("gcpkms(fake-server): GetPublicKey : unknown key %s", req.Name)
	}

	// forces response to be corrupt.
	if strings.Contains(req.Name, "ERROR_SRV_INTEGRITY") {
		resp.PemCrc32C = computeCRC32([]byte("error"))
	} else {
		resp.PemCrc32C = computeCRC32([]byte(resp.Pem))
	}
	return resp, nil
}

// Performs Asymmetric signing operations.
//
//   - If key name contains FORCE_ERROR_ON_ASYMMETRICSIGN returns an error.
//   - If key name contains with ERROR_RESP_INTEGRITY returned response does not match checksum.
//   - If key name contains with ERROR_REQ_INTEGRITY assumes request was corrupted in transit.
func (svc *fakeService) AsymmetricSign(_ context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	// If key set to force error, return an GRPC error response.
	if strings.Contains(req.Name, "FORCE_ERROR_ON_ASYMMETRICSIGN") {
		return nil, status.Error(codes.Internal, "fake service error")
	}

	resp := &kmspb.AsymmetricSignResponse{
		Name:                 req.Name,
		ProtectionLevel:      kmspb.ProtectionLevel_SOFTWARE,
		VerifiedDigestCrc32C: true,
	}

	if strings.Contains(req.Name, "ERROR_REQ_INTEGRITY") {
		resp.VerifiedDigestCrc32C = false
		return resp, nil
	}

	switch {
	// RSA PKCS1
	case strings.Contains(req.Name, "RSA_SIGN_PKCS1_2048_SHA256"):
		resp.Signature, _ = testkeys.GetRSA2048PrivateKey().Sign(
			rand.Reader, req.Digest.GetSha256(), crypto.SHA256,
		)
	case strings.Contains(req.Name, "RSA_SIGN_PKCS1_3072_SHA256"):
		resp.Signature, _ = testkeys.GetRSA3072PrivateKey().Sign(
			rand.Reader, req.Digest.GetSha256(), crypto.SHA256,
		)
	case strings.Contains(req.Name, "RSA_SIGN_PKCS1_4096_SHA256"):
		resp.Signature, _ = testkeys.GetRSA4096PrivateKey().Sign(
			rand.Reader, req.Digest.GetSha256(), crypto.SHA256,
		)
	case strings.Contains(req.Name, "RSA_SIGN_PKCS1_4096_SHA512"):
		resp.Signature, _ = testkeys.GetRSA4096PrivateKey().Sign(
			rand.Reader, req.Digest.GetSha512(), crypto.SHA512,
		)
	// EC Keys
	case strings.Contains(req.Name, "EC_SIGN_P256_SHA256"):
		resp.Signature, _ = testkeys.GetECP256PrivateKey().Sign(
			rand.Reader, req.Digest.GetSha256(), crypto.SHA256,
		)
	case strings.Contains(req.Name, "EC_SIGN_P384_SHA384"):
		resp.Signature, _ = testkeys.GetECP384PrivateKey().Sign(
			rand.Reader, req.Digest.GetSha384(), crypto.SHA384,
		)
	default:
		return nil, fmt.Errorf("gcpkms(fake-server):: AsymmetricSign unknown key %s",
			req.Name)
	}

	if strings.Contains(req.Name, "ERROR_RESP_INTEGRITY") {
		resp.SignatureCrc32C = computeCRC32([]byte("error"))
	} else {
		resp.SignatureCrc32C = computeCRC32(resp.Signature)
	}
	return resp, nil
}

// Performs Asymmetric decryption operations.
//
//   - If key name contains FORCE_ERROR_ON_ASYMMETRICDECTYPT returns an error.
//   - If key name contains with ERROR_RESP_INTEGRITY returned response does not match checksum.
//   - If key name contains with ERROR_REQ_INTEGRITY assumes request was corrupted in transit.
func (svc *fakeService) AsymmetricDecrypt(_ context.Context, req *kmspb.AsymmetricDecryptRequest) (*kmspb.AsymmetricDecryptResponse, error) {
	// If key set to force error, return an GRPC error response.
	if strings.Contains(req.Name, "FORCE_ERROR_ON_ASYMMETRICDECTYPT") {
		return nil, status.Error(codes.Internal, "fake service error")
	}

	resp := &kmspb.AsymmetricDecryptResponse{
		ProtectionLevel:          kmspb.ProtectionLevel_SOFTWARE,
		VerifiedCiphertextCrc32C: true,
	}

	if strings.Contains(req.Name, "ERROR_REQ_INTEGRITY") {
		resp.VerifiedCiphertextCrc32C = false
		resp.Plaintext = []byte(testkeys.KnownInput)
		resp.PlaintextCrc32C = computeCRC32(resp.Plaintext)
		return resp, nil
	}

	switch {
	case strings.Contains(req.Name, "RSA_DECRYPT_OAEP_2048_SHA1"):
		resp.Plaintext, _ = testkeys.GetRSA2048PrivateKey().Decrypt(
			rand.Reader, req.Ciphertext, &rsa.OAEPOptions{
				Hash: crypto.SHA1,
			})
	case strings.Contains(req.Name, "RSA_DECRYPT_OAEP_3072_SHA1"):
		resp.Plaintext, _ = testkeys.GetRSA3072PrivateKey().Decrypt(
			rand.Reader, req.Ciphertext, &rsa.OAEPOptions{
				Hash: crypto.SHA1,
			})
	case strings.Contains(req.Name, "RSA_DECRYPT_OAEP_4096_SHA1"):
		resp.Plaintext, _ = testkeys.GetRSA4096PrivateKey().Decrypt(
			rand.Reader, req.Ciphertext, &rsa.OAEPOptions{
				Hash: crypto.SHA1,
			})
	case strings.Contains(req.Name, "RSA_DECRYPT_OAEP_2048_SHA256"):
		resp.Plaintext, _ = testkeys.GetRSA2048PrivateKey().Decrypt(
			rand.Reader, req.Ciphertext, &rsa.OAEPOptions{
				Hash: crypto.SHA256,
			})
	case strings.Contains(req.Name, "RSA_DECRYPT_OAEP_3072_SHA256"):
		resp.Plaintext, _ = testkeys.GetRSA3072PrivateKey().Decrypt(
			rand.Reader, req.Ciphertext, &rsa.OAEPOptions{
				Hash: crypto.SHA256,
			})
	case strings.Contains(req.Name, "RSA_DECRYPT_OAEP_4096_SHA256"):
		resp.Plaintext, _ = testkeys.GetRSA4096PrivateKey().Decrypt(
			rand.Reader, req.Ciphertext, &rsa.OAEPOptions{
				Hash: crypto.SHA256,
			})
	case strings.Contains(req.Name, "RSA_DECRYPT_OAEP_4096_SHA512"):
		resp.Plaintext, _ = testkeys.GetRSA4096PrivateKey().Decrypt(
			rand.Reader, req.Ciphertext, &rsa.OAEPOptions{
				Hash: crypto.SHA512,
			})
	default:
		return nil, fmt.Errorf("gcpkms(fake-server): AsymmetricDecrypt unknown key %s", req.Name)
	}

	if strings.Contains(req.Name, "ERROR_RESP_INTEGRITY") {
		resp.PlaintextCrc32C = computeCRC32([]byte("error"))
	} else {
		resp.PlaintextCrc32C = computeCRC32(resp.Plaintext)
	}
	return resp, nil
}
