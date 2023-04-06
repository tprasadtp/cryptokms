package ioutils

import (
	"fmt"
	"os"
	"strings"
	"text/template"
	"time"
)

// Renders a single template to output.
//   - If output file does not exist it is created.
//   - If output file exists, it is overwritten.
func RenderTemplate(output string, tpl string, data any) error {
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

	// create file if required.
	file, err := os.OpenFile(
		output,
		os.O_CREATE|os.O_TRUNC|os.O_WRONLY,
		0644,
	)
	if err != nil {
		return fmt.Errorf("cryptokms(ioutils): failed to create file %s: %w", output, err)
	}
	defer file.Close()

	// we truncated the file, so it is highly unlikely that write here fails.
	// thus it is not covered by unit tests.
	err = t.Execute(file, data)
	if err != nil {
		return fmt.Errorf("cryptokms(ioutils): failed to write template: %w", err)
	}
	return nil
}
