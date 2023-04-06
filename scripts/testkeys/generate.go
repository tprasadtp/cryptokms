package main

import (
	_ "embed"
	"flag"
	"log"
	"path/filepath"

	"github.com/tprasadtp/cryptokms/internal/ioutils"
)

var output string

var (
	//go:embed keys.go.tpl
	keysTpl string
)

type Keys struct {
	RSA []int
	EC  []int
}

func main() {
	flag.StringVar(&output, "output", "", "Output directory (required)")
	flag.Parse()

	if output == "" {
		log.Fatalf("output not specified")
	}

	data := Keys{
		RSA: []int{2048, 3072, 4096},
		EC:  []int{256, 384, 521},
	}

	log.Printf("Rendering template - keys.go.tpl")
	keysOutputFile := filepath.Join(output, "keys.go")
	err := ioutils.RenderTemplate(keysOutputFile, keysTpl, data)
	if err != nil {
		log.Fatalf("failed to render keys.go: %s", err)
	}
}
