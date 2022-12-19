//go:build ignore

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"text/template"
)

func renderTemplate(tpl string, output string, data any) {
	b := template.New(tpl).Funcs(template.FuncMap{
		"lower": strings.ToLower,
	})
	t, err := b.ParseFiles(tpl)
	if err != nil {
		log.Fatalf("Failed to parse template %s: %s", tpl, err)
	}
	file, err := os.OpenFile(
		output,
		os.O_CREATE|os.O_TRUNC|os.O_WRONLY,
		0644,
	)
	if err != nil {
		log.Fatalf("Failed to open/create file: %s", err)
	}

	err = t.Execute(file, data)
	if err != nil {
		file.Close()
		log.Fatalf("Failed to render template %s to %s : %s", tpl, output, err)
	}
	file.Close()
}

// Generate RSA code.
func genRSAGoCode() {
	type RSATemplateParams struct {
		Size      uint
		EmbedFile string
	}

	for _, bits := range []uint{1024, 2048, 3072, 4096} {
		ktype := fmt.Sprintf("RSA (%d)", bits)
		fname := fmt.Sprintf("rsa_%d.go", bits)
		ftname := fmt.Sprintf("rsa_%d_test.go", bits)
		log.Printf("Generate go code: %s", ktype)
		params := RSATemplateParams{
			Size: bits,
		}
		renderTemplate("rsa.go.tpl", fname, params)
		renderTemplate("rsa_test.go.tpl", ftname, params)
	}
}

// Generate ECDSA code.
func genECGoCode() {
	type ECTemplateParams struct {
		Size      int
		EmbedFile string
	}
	for _, size := range []int{256, 384, 521} {
		ktype := fmt.Sprintf("EC (P-%d)", size)
		fname := fmt.Sprintf("ecdsa_p%d.go", size)
		ftname := fmt.Sprintf("ecdsa_p%d_test.go", size)
		log.Printf("Generate go code: %s", ktype)
		params := ECTemplateParams{
			Size: size,
		}
		renderTemplate("ecdsa.go.tpl", fname, params)
		renderTemplate("ecdsa_test.go.tpl", ftname, params)
	}
}

func main() {
	var gentype string
	flag.StringVar(&gentype, "type", "", "Type to generate. can be 'go'")
	flag.Parse()
	switch gentype {
	case "go", "code", "gocode":
		genRSAGoCode()
		genECGoCode()
	default:
		log.Fatalf("Unknown mode or not specified: %s", gentype)
	}
}
