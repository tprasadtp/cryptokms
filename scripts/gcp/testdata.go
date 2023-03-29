package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/google/go-replayers/grpcreplay"
	"github.com/tprasadtp/cryptokms/gcpkms"
	"github.com/tprasadtp/cryptokms/internal/shared"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
	"google.golang.org/api/option"
)

// metadata.go code template.
//
//go:embed metadata.go.tpl
var metadataGoTpl string

type opts struct {
	ConfigFile      string
	Config          Config
	CredentialsJSON string
	Output          string
	TemplatesOnly   bool
}

type Config struct {
	ProjectName     string `json:"ProjectName"`
	KeyringName     string `json:"KeyringName"`
	KeyringLocation string `json:"KeyringLocation"`
	Keys            []Key  `json:"Keys"`
}

type Key struct {
	KeyID        string `json:"KeyID"`
	KeyAlgorithm string `json:"KeyAlgorithm"`
	KeyUsage     string `json:"KeyUsage"`
}

// Generates test data.
//
//nolint:funlen // test code
func (o *opts) GenerateTestData(ctx context.Context, keyID, keyUsage, keyAlgorithm string) error {
	var err error

	fileNameBase := filepath.Base(strings.ToLower(strings.ReplaceAll(keyID, "_", "-")))

	replayFile := filepath.Join(o.Output, fileNameBase+".replay")
	log.Printf("Generating playback - %s", replayFile)
	rec, err := grpcreplay.NewRecorder(replayFile, nil)
	if err != nil {
		return fmt.Errorf("failed to create recorder %s: %w", fileNameBase, err)
	}
	defer rec.Close()

	opts := make([]option.ClientOption, 0, 10)
	for _, item := range rec.DialOptions() {
		opts = append(opts, option.WithGRPCDialOption(item))
	}

	if o.CredentialsJSON != "" {
		log.Printf("Using Credentials - %s", o.CredentialsJSON)
		opts = append(opts, option.WithCredentialsFile(o.CredentialsJSON))
	}

	log.Printf("Creating KMS client - %s", fileNameBase)
	client, err := kms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to create KMS client: %w", err)
	}

	var pub crypto.PublicKey
	switch keyUsage {
	case "ASYMMETRIC_SIGN":
		log.Printf("Creating Signer - %s[%s]", keyID, keyAlgorithm)
		var signer *gcpkms.Signer
		var signature []byte

		signer, err = gcpkms.NewSigner(ctx, client, fmt.Sprintf("%s/cryptoKeyVersions/1", keyID))
		if err != nil {
			return fmt.Errorf("failed to create signer: %w", err)
		}
		pub = signer.Public()
		log.Printf("Signing - %s[%s]", keyID, keyAlgorithm)
		signature, err = signer.SignContext(
			ctx, rand.Reader, testkeys.KnownInputHash(signer.HashFunc()), nil)
		if err != nil {
			return fmt.Errorf("failed to sign: %w", err)
		}
		signatureFile := filepath.Join(o.Output, fileNameBase+".sig")
		log.Printf("Save signature to - %s", signatureFile)
		err = shared.WriteBinaryBlob(signatureFile, signature)
		if err != nil {
			return fmt.Errorf("failed to write signature to %s: %w", signatureFile, err)
		}
	case "ASYMMETRIC_DECRYPT":
		log.Printf("Creating Decrypter - %s", keyID)
		var decrypter *gcpkms.Decrypter
		var encrypted []byte
		decrypter, err = gcpkms.NewDecrypter(
			ctx, client, fmt.Sprintf("%s/cryptoKeyVersions/1", keyID))
		if err != nil {
			return fmt.Errorf("failed to create decrypter: %w", err)
		}
		pub = decrypter.Public()
		log.Printf("Encrypting via Public Key - %s", keyID)
		encrypted, err = rsa.EncryptOAEP(
			decrypter.HashFunc().New(),
			rand.Reader,
			decrypter.Public().(*rsa.PublicKey),
			[]byte(testkeys.KnownInput),
			nil)
		if err != nil {
			return fmt.Errorf("failed to encrypt: %w", err)
		}

		encryptedFile := filepath.Join(o.Output, fileNameBase+".crypt")
		log.Printf("Save encrypted text to - %s", encryptedFile)
		err = shared.WriteBinaryBlob(encryptedFile, encrypted)
		if err != nil {
			return fmt.Errorf("failed to write encrypted text to %s: %w", encryptedFile, err)
		}

		log.Printf("Decrypting via KMS - %s", keyID)
		_, err = decrypter.DecryptContext(ctx, nil, encrypted, nil)
		if err != nil {
			return fmt.Errorf("failed to decrypt via KMS: %w", err)
		}
	default:
		return fmt.Errorf("unknown KeyUsage: %s", keyUsage)
	}

	publicKeyFile := filepath.Join(o.Output, fileNameBase+".pub")
	log.Printf("Save PublicKey to - %s", publicKeyFile)
	err = shared.WritePublicKey(publicKeyFile, pub)
	if err != nil {
		return fmt.Errorf("testdata: %w", err)
	}
	return nil
}

// Read config and generate test data.
func (o *opts) RunE(ctx context.Context) error {
	log.Printf("Parsing Config JSON")
	jb, err := os.ReadFile(o.ConfigFile)
	if err != nil {
		return fmt.Errorf("failed to read config JSON (%s): %w", o.ConfigFile, err)
	}

	err = json.Unmarshal(jb, &o.Config)
	if err != nil {
		return fmt.Errorf("failed to parse config JSON(%s): %w", o.ConfigFile, err)
	}

	if !o.TemplatesOnly {
		for _, k := range o.Config.Keys {
			err = o.GenerateTestData(ctx, k.KeyID, k.KeyUsage, k.KeyAlgorithm)
			if err != nil {
				return fmt.Errorf(
					"failed to generate test data (%s): %w",
					filepath.Base(k.KeyID), err)
			}
		}
	}

	// generate keyring and project info.
	// key resource name includes keyring, location and project.
	// this we export them as constants in testdata package
	// to be used by test code.
	metadataFileName := filepath.Join(o.Output, "metadata.go")
	log.Printf("Writing: %s", metadataFileName)
	err = shared.RenderTemplate(metadataFileName, metadataGoTpl, o)
	if err != nil {
		log.Fatalf("failed to create file - %s: %s", metadataFileName, err)
	}

	// Write content file
	dataFileName := filepath.Join(o.Output, "data.txt")
	log.Printf("Writing: %s", dataFileName)
	err = shared.WriteBinaryBlob(dataFileName, []byte(testkeys.KnownInput))
	if err != nil {
		log.Fatalf("failed to write data file - %s: %s", dataFileName, err)
	}
	return nil
}

func main() {
	o := opts{}
	flag.StringVar(&o.ConfigFile, "config", "", "Config JSON (required)")
	flag.BoolVar(&o.TemplatesOnly, "templates-only", false, "Skip sign/decrypt only render templates")
	flag.StringVar(&o.CredentialsJSON, "credentials", "", "GCP service account JSON")
	flag.StringVar(&o.Output, "output", "", "Directory to save grpc responses and templates (required)")
	flag.Parse()

	if o.ConfigFile == "" {
		log.Fatalf("config JSON not specified")
	}

	if o.Output == "" {
		log.Fatalf("output directory not specified")
	}

	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt)
	if err := o.RunE(ctx); err != nil {
		log.Fatal(err)
	}
}
