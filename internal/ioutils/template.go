package ioutils

import (
	"fmt"
	"os"
	"text/template"
)

// Renders a single template to output.
//   - If output file does not exist it is created.
//   - If output file exists, it is overwritten.
func RenderTemplate(output string, tpl string, data any) error {
	t, err := template.New("template.go.tpl").Parse(tpl)
	if err != nil {
		return fmt.Errorf("cryptokms(shared): failed to parse template: %w", err)
	}

	// create file if required.
	file, err := os.OpenFile(
		output,
		os.O_CREATE|os.O_TRUNC|os.O_WRONLY,
		0644,
	)
	if err != nil {
		return fmt.Errorf("cryptokms(shared): failed to create file %s: %w", output, err)
	}
	defer file.Close()

	// we truncated the file, so it is highly unlikely that write here fails.
	// thus it is not covered by unit tests.
	err = t.Execute(file, data)
	if err != nil {
		return fmt.Errorf("cryptokms(shared): failed to write template: %w", err)
	}
	return nil
}
