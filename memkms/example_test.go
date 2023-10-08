// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package memkms_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"

	"github.com/tprasadtp/cryptokms"
	"github.com/tprasadtp/cryptokms/memkms"
)

const Key = `
-----BEGIN PRIVATE KEY-----
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
+8CUjAuwrbsmTxncKFn5uS1gaieOBQ==
-----END PRIVATE KEY-----
`

func ExampleSigner() {
	ctx := context.Background()

	// Create a new Signer.
	signer, err := memkms.NewSigner(Key)
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

	// Create a new Decrypter
	decrypter, err := memkms.NewDecrypter(Key)
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
