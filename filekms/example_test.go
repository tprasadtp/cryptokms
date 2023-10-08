// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package filekms_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"

	"github.com/tprasadtp/cryptokms"
	"github.com/tprasadtp/cryptokms/filekms"
)

func ExampleSigner() {
	ctx := context.Background()

	// Please replace this with path to your PEM encoded key file.
	keyFile := "internal/testdata/ec-p256.pem"

	// Create a new Signer.
	signer, err := filekms.NewSigner(keyFile)
	if err != nil {
		// TODO: Handle error
		panic(err)
	}

	// Message you want to sign
	// A nod to https://en.wikipedia.org/wiki/Stellar_classification.
	msg := []byte(`Oh Be A Fine Girl Kiss Me`)

	// hash the message you want to sign.
	// with defined hash function.
	h := signer.HashFunc().New()
	h.Write(msg)
	digest := h.Sum(nil)

	// Sign the digest
	signature, err := signer.SignContext(ctx, nil, digest, nil)
	if err != nil {
		// TODO: Handle error
		panic(err)
	}

	// Verify the signature
	err = cryptokms.VerifyDigestSignature(signer.Public(), signer.HashFunc(), digest, signature)
	if err != nil {
		// TODO: Handle error
		panic(err)
	}
	fmt.Printf("Digest   : %s\n", hex.EncodeToString(digest))
	fmt.Printf("Signature: Verified\n")

	// Output:
	// Digest   : 381d492615cee4337ef441d9fb2e3682c0306fb99b82ff966af4cc5dc8db61b7
	// Signature: Verified
}

func ExampleDecrypter() {
	ctx := context.Background()

	// Please replace this with path to your PEM encoded key file.
	keyFile := "internal/testdata/rsa-3072.pem"

	// Create a new Decrypter
	decrypter, err := filekms.NewDecrypter(keyFile)
	if err != nil {
		// TODO: Handle error
		panic(err)
	}

	// Message you want to encrypt
	// A nod to https://en.wikipedia.org/wiki/Stellar_classification.
	msg := []byte(`Oh Be A Fine Girl Kiss Me`)

	// Encrypt the message using public key.
	encrypted, err := rsa.EncryptOAEP(
		decrypter.HashFunc().New(),
		rand.Reader,
		decrypter.Public().(*rsa.PublicKey),
		msg,
		nil,
	)
	if err != nil {
		// TODO: Handle error
		panic(err)
	}

	// Decrypt the message
	plaintext, err := decrypter.DecryptContext(ctx, nil, encrypted, nil)
	if err != nil {
		// TODO: Handle error
		panic(err)
	}

	fmt.Printf("Plaintext: %s", string(plaintext))
	// Output:
	// Plaintext: Oh Be A Fine Girl Kiss Me
}
