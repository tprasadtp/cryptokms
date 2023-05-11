package fakekms_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/tprasadtp/cryptokms"
	"github.com/tprasadtp/cryptokms/fakekms"
)

func ExampleSigner() {
	ctx := context.Background()

	// Create a fakekms signer
	signer, err := fakekms.NewSigner("rsa-2048")
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

	// Sign the digest with PKCSv15 signature scheme
	signature, err := signer.SignContext(ctx, nil, digest, signer.SignerOpts())
	if err != nil {
		// TODO: Handle error
		panic(err)
	}

	// Verify the signature
	err = cryptokms.VerifyDigestSignature(signer.Public(), signer.HashFunc(), digest, signature)
	if err != nil {
		// TODO: Handle error
		panic(err)
	} else {
		fmt.Println("Verified")
	}
	// Output: Verified
}

func ExampleDecrypter() {
	ctx := context.Background()

	// Create a new Decrypter
	decrypter, err := fakekms.NewDecrypter("rsa-2048")
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

	// Encrypt the message using public key and default hash function.
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

	// Decrypt the message using default decrypter options.
	plaintext, err := decrypter.DecryptContext(ctx, nil, encrypted, decrypter.DecrypterOpts())
	if err != nil {
		// TODO: Handle error
		panic(err)
	}

	fmt.Printf("Plaintext: %s", string(plaintext))
	//Output: Plaintext: Oh Be A Fine Girl Kiss Me
}
