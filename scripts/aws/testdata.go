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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/google/go-replayers/httpreplay"
	"github.com/tprasadtp/cryptokms/awskms"
	"github.com/tprasadtp/cryptokms/internal/ioutils"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

// metadata.go code template.
//
//go:embed metadata.go.tpl
var metadataGoTpl string

type opts struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Region          string
	KMSEndpoint     string
	ConfigFile      string
	Config          Config
	Output          string
	TemplatesOnly   bool
}

var (
	_ kms.EndpointResolver    = (*opts)(nil)
	_ aws.CredentialsProvider = (*opts)(nil)
)

type Config struct {
	Keys []Key `json:"Keys"`
}

type Key struct {
	KeyID        string `json:"KeyID"`
	KeyAlgorithm string `json:"KeyAlgorithm"`
	KeyUsage     string `json:"KeyUsage"`
}

// Implements [github.com/aws/aws-sdk-go-v2/aws.CredentialsProvider].
func (o *opts) Retrieve(ctx context.Context) (aws.Credentials, error) {
	return aws.Credentials{
		AccessKeyID:     o.AccessKeyID,
		SecretAccessKey: o.SecretAccessKey,
		SessionToken:    o.SessionToken,
	}, nil
}

// Implements [github.com/aws/aws-sdk-go-v2/kms.EndpointResolver].
func (o *opts) ResolveEndpoint(region string, options kms.EndpointResolverOptions) (aws.Endpoint, error) {
	return aws.Endpoint{
		URL: o.KMSEndpoint,
	}, nil
}

// generate testdata for a single key.
//
//nolint:funlen // test code
func (o *opts) GenerateTestData(ctx context.Context, keyID, keyUsage, keyAlgorithm string) error {
	var err error
	log.Printf("Key ARN=%s, usage=%s algo=%s", keyID, keyUsage, keyAlgorithm)

	fileNameBase := fmt.Sprintf("%s-%s",
		strings.ToLower(strings.ReplaceAll(keyUsage, "_", "-")),
		strings.ToLower(strings.ReplaceAll(keyAlgorithm, "_", "-")),
	)

	replayFile := filepath.Join(o.Output, fileNameBase+".replay.json")
	log.Printf("Generating playback - %s", replayFile)
	rec, err := httpreplay.NewRecorder(replayFile, nil)
	if err != nil {
		return fmt.Errorf("failed to setup http recorder %s: %w", keyID, err)
	}
	defer rec.Close() // important, otherwise replayer is invalid.
	rec.RemoveRequestHeaders(
		"User-Agent",            // varies based on sdk version
		"X-Amz-Date",            // ignore
		"X-Amz-Credential",      // scrub credentials
		"X-Amz-Security-Token",  // scrub sts token
		"X-Amz-Signature",       // scrub signature
		"Amz-Sdk-Invocation-Id", // ignore
	)

	kmsOptions := kms.Options{
		Credentials: o,
		Region:      o.Region,
		HTTPClient:  rec.Client(),
	}

	if o.KMSEndpoint != "" {
		kmsOptions.EndpointResolver = o
	}

	// We want to avoid a call to sts service
	// as it gets recorded as well, so we don't use any aws cli configs.
	client := kms.New(kmsOptions)

	// Based on interface switch flow.
	var pub crypto.PublicKey
	switch keyUsage {
	case "SIGN_VERIFY":
		log.Printf("Creating Signer - %s[%s]", keyID, keyAlgorithm)
		signer, err := awskms.NewSigner(ctx, client, keyID)
		if err != nil {
			return fmt.Errorf("failed to build signer: %w", err)
		}
		pub = signer.Public()
		log.Printf("Signing - %s[%s]", keyID, keyAlgorithm)
		signature, err := signer.SignContext(
			ctx, rand.Reader, testkeys.KnownInputHash(signer.HashFunc()), nil)
		if err != nil {
			return fmt.Errorf("failed to sign: %w", err)
		}

		signatureFile := filepath.Join(o.Output, fileNameBase+".sig")
		log.Printf("Save signature to - %s", signatureFile)
		err = ioutils.WriteBlob(signatureFile, signature)
		if err != nil {
			return fmt.Errorf("failed to write signature to %s: %w", signatureFile, err)
		}
	case "ENCRYPT_DECRYPT":
		log.Printf("Creating Decrypter - %s[%s]", keyID, keyAlgorithm)
		decrypter, err := awskms.NewDecrypter(ctx, client, keyID)
		if err != nil {
			return fmt.Errorf("failed to build decrypter: %w", err)
		}
		pub = decrypter.Public()

		encrypted, err := rsa.EncryptOAEP(
			decrypter.HashFunc().New(),
			rand.Reader,
			pub.(*rsa.PublicKey),
			[]byte(testkeys.KnownInput),
			nil)
		if err != nil {
			return fmt.Errorf("failed to encrypt: %w", err)
		}

		encryptedFile := filepath.Join(o.Output,
			fmt.Sprintf("%s.crypt", fileNameBase),
		)
		log.Printf("Save encrypted text to - %s", encryptedFile)
		err = ioutils.WriteBlob(encryptedFile, encrypted)
		if err != nil {
			return fmt.Errorf("failed to write encrypted text to %s: %w", encryptedFile, err)
		}

		log.Printf("Decrypting via KMS - %s", keyID)
		_, err = decrypter.DecryptContext(ctx, nil, encrypted, nil)
		if err != nil {
			return fmt.Errorf("failed to decrypt via KMS: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unknown key usage=%s", keyUsage)
	}

	publicKeyFile := filepath.Join(o.Output, fileNameBase+".pub")
	log.Printf("Save PublicKey to - %s", publicKeyFile)
	err = ioutils.WritePublicKey(publicKeyFile, pub)
	if err != nil {
		return fmt.Errorf("testdata: %w", err)
	}
	return nil
}

// Read config and generate test data.
func (o *opts) RunE(ctx context.Context) error {
	if o.Output == "" {
		return fmt.Errorf("output directory not specified")
	}

	//nolint:nestif // flag fallback to env vars.
	if !o.TemplatesOnly {
		if o.AccessKeyID == "" {
			o.AccessKeyID = os.Getenv("AWS_ACCESS_KEY_ID")
		}
		if o.SecretAccessKey == "" {
			o.SecretAccessKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
		}
		if o.SessionToken == "" {
			o.SessionToken = os.Getenv("AWS_SESSION_TOKEN")
		}
		if o.AccessKeyID == "" {
			return fmt.Errorf("-access-key-id(AWS_ACCESS_KEY_ID) not specified")
		}

		if o.SecretAccessKey == "" {
			return fmt.Errorf("-secret-access-key(AWS_SECRET_ACCESS_KEY) not specified")
		}

		if strings.HasPrefix(o.AccessKeyID, "ASIA") {
			if o.SessionToken == "" {
				return fmt.Errorf("-session-token(AWS_SESSION_TOKEN) not specified")
			}
		}
	}

	// This is special as it is also used during rendering templates.
	if o.Region == "" {
		o.Region = os.Getenv("AWS_REGION")
	}

	if o.Region == "" {
		return fmt.Errorf("AWS Region (-region/AWS_REGION) not specified")
	}

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
					"failed to generate test data %s(%s): %w", k.KeyAlgorithm, k.KeyUsage, err)
			}
		}
	}

	// generate keyring and key arn info.
	// key resource name includes location and arn data.
	metadataFileName := filepath.Join(o.Output, "metadata.go")
	log.Printf("Writing: %s", metadataFileName)
	err = ioutils.RenderTemplate(metadataFileName, metadataGoTpl, o)
	if err != nil {
		log.Fatalf("failed to create file - %s: %s", metadataFileName, err)
	}

	// Write content file
	dataFileName := filepath.Join(o.Output, "data.txt")
	log.Printf("Writing: %s", dataFileName)
	err = ioutils.WriteBlob(dataFileName, []byte(testkeys.KnownInput))
	if err != nil {
		log.Fatalf("failed to write data file - %s: %s", dataFileName, err)
	}
	return nil
}

func main() {
	o := opts{}
	flag.StringVar(&o.ConfigFile, "config", "", "Config JSON (required)")
	flag.BoolVar(&o.TemplatesOnly, "templates-only", false, "Skip sign/decrypt only render templates")
	flag.StringVar(&o.Region, "region", "", "AWS Region (required)")
	flag.StringVar(&o.AccessKeyID, "access-key-id", "", "AWS Access Key ID (required)")
	flag.StringVar(&o.KMSEndpoint, "kms-endpoint", "", "AWS KMS API endpoint URL")
	flag.StringVar(&o.SecretAccessKey, "secret-access-key", "", "AWS Secret Access Key (required)")
	flag.StringVar(&o.SessionToken, "session-token", "", "AWS Session Token")
	flag.StringVar(&o.Output, "output", "", "Directory to save test data (required)")
	flag.Parse()

	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt)
	if err := o.RunE(ctx); err != nil {
		log.Fatalf("%s", err)
	}
}
