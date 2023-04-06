package ioutils_test

import (
	"path/filepath"
	"testing"

	"github.com/tprasadtp/cryptokms/internal/ioutils"
)

type Data struct {
	Name string
}

func Test_RenderMetadata(t *testing.T) {
	type testCase struct {
		Name     string
		Template string
		Output   string
		Data     any
		Err      bool
	}

	dir := t.TempDir()
	tt := []testCase{
		{
			Name:     "valid-template",
			Template: `Hello, {{ .Name | replace "Go" "Golang" | lower | upper }}`,
			Output:   filepath.Join(dir, "valid-template"),
			Data: struct {
				Name string
			}{
				Name: "Go Unit Test",
			},
		},
		{
			Name:     "invalid-template",
			Template: "Hello, {{ .Name }",
			Output:   filepath.Join(dir, "invalid-template"),
			Err:      true,
			Data: struct {
				Name string
			}{
				Name: "Go Unit Test",
			},
		},
		{
			Name:     "non-existent-output-path",
			Template: "Hello, {{ .Name }}",
			Output:   "/33ae370d-83d0-5819-bc18-8cd899168bb4/3e5c6c6f-49aa-5607-a239-5f985d7eaf66",
			Err:      true,
			Data: struct {
				Name string
			}{
				Name: "Go Unit Test",
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			err := ioutils.RenderTemplate(tc.Output, tc.Template, tc.Data)
			if tc.Err {
				if err == nil {
					t.Errorf("expected to error, got nil")
				}
			} else {
				if err != nil {
					t.Error("unexpected error")
				}
			}
		})
	}
}
