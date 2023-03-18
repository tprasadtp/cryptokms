package shared

import (
	"fmt"
	"os"
)

// WriteBinaryBlob writes given binary blob to file.
//   - If output file does not exist it is created.
//   - If output file exists, it is overwritten.
func WriteBinaryBlob(output string, blob []byte) error {
	if len(blob) == 0 {
		return fmt.Errorf("shared(blob): blob is empty")
	}
	// create file if required.
	file, err := os.OpenFile(
		output,
		os.O_CREATE|os.O_TRUNC|os.O_WRONLY,
		0644,
	)
	if err != nil {
		return fmt.Errorf("shared(blob): failed to create file %s: %w", output, err)
	}
	defer file.Close()

	// we truncated the file, so it is highly unlikely that write here fails.
	// thus it is not covered by unit tests.
	_, err = file.Write(blob)
	if err != nil {
		return fmt.Errorf("shared(blob): failed to write blob: %w", err)
	}
	return nil
}
