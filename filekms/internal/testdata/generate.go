// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	"os"
	"path/filepath"
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
			priv: func() crypto.PrivateKey {
				log.Printf("Generating ED25519 key....")
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					log.Fatalf("failed to generate ED25519 key: %s", err)
				}
				return priv
			}(),
		},
		{
			name: "RSA-1024",
			priv: func() crypto.PrivateKey {
				log.Printf("Generating RSA-1024 key....")
				//nolint:gosec // test to ensure 1024 bit keys is rejected.
				priv, err := rsa.GenerateKey(rand.Reader, 1024)
				if err != nil {
					log.Fatalf("failed to generate RSA-1024 key: %s", err)
				}
				return priv
			}(),
		},
	}
	for _, item := range gs {
		err := CreatePrivateKeyFile(item.name, item.priv)
		if err != nil {
			log.Fatalf("failed to generate: %s: %s", item.name, err)
		}
	}
}

//nolint:wrapcheck // ignore
func CreatePrivateKeyFile(name string, priv crypto.PrivateKey) error {
	log.Printf("Creating file - %s", strings.ToLower(name)+".pub")
	file, err := os.Create(filepath.Join(output, strings.ToLower(name)+".pem"))
	if err != nil {
		return err
	}
	defer file.Close()

	b, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}

	pem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	})

	_, err = file.Write(pem)
	if err != nil {
		return err
	}

	err = file.Close()
	if err != nil {
		return err
	}
	return nil
}
