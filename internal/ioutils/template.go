package ioutils

import (
	"bytes"
	"fmt"
	"go/format"
	"strings"
	"text/template"
	"time"
)

// Renders a single go template to output.
//   - If output file does not exist it is created.
//   - If output file exists, it is overwritten.
//   - Rendered output is formatted with gofmt.
func RenderGoTemplate(output string, tpl string, data any) error {
	t := template.New("template.go.tpl").Funcs(
		template.FuncMap{
			"lower": strings.ToLower,
			"upper": strings.ToUpper,
			"now":   time.Now,
			"replace": func(find, replace, input string) string {
				return strings.ReplaceAll(input, find, replace)
			},
		},
	)
	t, err := t.Parse(tpl)
	if err != nil {
		return fmt.Errorf("cryptokms(ioutils): failed to parse template: %w", err)
	}

	// Render Template
	var buf = &bytes.Buffer{}
	err = t.Execute(buf, data)
	if err != nil {
		return fmt.Errorf("cryptokms(ioutils): failed to render template: %w", err)
	}

	// Format Template Output
	bw, err := format.Source(buf.Bytes())
	if err != nil {
		return fmt.Errorf("cryptokms(ioutils): failed to format rendered template: %w", err)
	}

	return WriteBlob(output, bw)
}