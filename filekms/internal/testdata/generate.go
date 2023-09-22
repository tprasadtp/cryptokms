// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	"os"
	"strings"

	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

var output string

type Key struct {
	name string
	priv crypto.PrivateKey
}

func main() {
	flag.StringVar(&output, "output", "", "output directory")
	flag.Parse()

	log.Printf("Generating keys....")
	gs := []Key{
		{
			name: "RSA-2048",
			priv: testkeys.GetRSA2048PrivateKey(),
		},
		{
			name: "RSA-3072",
			priv: testkeys.GetRSA3072PrivateKey(),
		},
		{
			name: "RSA-4096",
			priv: testkeys.GetRSA4096PrivateKey(),
		},
		{
			name: "EC-P256",
			priv: testkeys.GetECP256PrivateKey(),
		},
		{
			name: "EC-P384",
			priv: testkeys.GetECP384PrivateKey(),
		},
		{
			name: "EC-P521",
			priv: testkeys.GetECP521PrivateKey(),
		},
		{
			name: "ED-25519",
			priv: testkeys.GetED25519PrivateKey(),
		},
		{
			name: "RSA-1024",
			priv: func() crypto.PrivateKey {
				log.Printf("Generating RSA-1024 key....")
				//nolint:gosec // keys are used to ensure 1024 bit keys is rejected.
				priv, err := rsa.GenerateKey(rand.Reader, 1024)
				if err != nil {
					log.Fatalf("failed to generate RSA-1024 key: %s", err)
				}
				return priv
			}(),
		},
	}
	for _, item := range gs {
		err := CreatePKCS8File(strings.ToLower(item.name)+".pem", item.priv)
		if err != nil {
			log.Fatalf("failed to generate: %s: %s", item.name, err)
		}

		switch v := item.priv.(type) {
		case *rsa.PrivateKey:
			err = CreatePKCS1File(strings.ToLower(item.name)+".pkcs1.pem", v)
			if err != nil {
				log.Fatalf("failed to generate: %s: %s", item.name, err)
			}
		case *ecdsa.PrivateKey:
			err = CreateECPrivateKey(strings.ToLower(item.name)+".ec.pem", v)
			if err != nil {
				log.Fatalf("failed to generate: %s: %s", item.name, err)
			}
		}
	}
}

func CreatePKCS8File(name string, priv crypto.PrivateKey) error {
	b, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}

	pem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	})

	err = CreateFileWithData(name, pem)
	if err != nil {
		return err
	}
	return nil
}

func CreatePKCS1File(name string, priv *rsa.PrivateKey) error {
	b := x509.MarshalPKCS1PrivateKey(priv)
	pem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: b,
	})

	err := CreateFileWithData(name, pem)
	if err != nil {
		return err
	}
	return nil
}

func CreateECPrivateKey(name string, priv *ecdsa.PrivateKey) error {
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}

	pem := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: b,
	})

	err = CreateFileWithData(name, pem)
	if err != nil {
		return err
	}
	return nil
}

func CreateFileWithData(name string, data []byte) error {
	log.Printf("Creating file - %s", name)
	file, err := os.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return err
	}

	err = file.Close()
	if err != nil {
		return err
	}
	return nil
}
