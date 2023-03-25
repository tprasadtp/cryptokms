package awskms_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/tprasadtp/cryptokms"
	"github.com/tprasadtp/cryptokms/awskms"
)

func ExampleSigner() {
	ctx := context.Background()

	// Create a New KMS client
	client := kms.New(kms.Options{Region: "us-east-1"})

	// Key Version Resource name.
	// Please replace this with your KMS Key ARN.
	keyID := "arn:aws:kms:us-east-1:000000000000:key/6ac3332a-9900-4c0d-8de2-a8f8748700ff"

	// Create a new Signer.
	signer, err := awskms.NewSigner(ctx, client, keyID)
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
}

func ExampleDecrypter() {
	ctx := context.Background()

	// Create a New KMS client
	client := kms.New(kms.Options{Region: "us-east-1"})

	// Key Version Resource name.
	// Please replace this with your KMS Key ARN.
	keyID := "arn:aws:kms:us-east-1:000000000000:key/6ac3332a-9900-4c0d-8de2-a8f8748700ff"

	// Create a new Decrypter
	decrypter, err := awskms.NewDecrypter(ctx, client, keyID)
	if err != nil {
		// TODO: Handle error
		panic(err)
	}

	// Message you want to encrypt
	// A nod to https://en.wikipedia.org/wiki/Stellar_classification.
	msg := []byte(`Oh Be A Fine Girl Kiss Me`)

	// This should not be really necessary as currently only asymmetric keys supported
	// for encryption are RSA keys.
	pub, ok := decrypter.Public().(*rsa.PublicKey)
	if !ok {
		// TODO: Handle error
		panic("not rsa key")
	}

	// Encrypt the message using public key.
	encrypted, err := rsa.EncryptOAEP(
		decrypter.HashFunc().New(),
		rand.Reader,
		pub,
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
}
