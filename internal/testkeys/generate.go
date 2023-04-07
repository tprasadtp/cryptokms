//go:build ignore

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
	//go:embed keys_test.go.tpl
	keysTestTpl string
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
	err := ioutils.RenderGoTemplate(keysOutputFile, keysTpl, data)
	if err != nil {
		log.Fatalf("failed to render keys.go: %s", err)
	}

	log.Printf("Rendering template - keys_test.go.tpl")
	keysTestOutputFile := filepath.Join(output, "keys_test.go")
	err = ioutils.RenderGoTemplate(keysTestOutputFile, keysTestTpl, data)
	if err != nil {
		log.Fatalf("failed to render keys_test.go: %s", err)
	}
}
