package cryptokms_test

import (
	"strings"
	"testing"

	"github.com/tprasadtp/cryptokms"
)

func Test_Backend_String_Ensure_TrimPrefix(t *testing.T) {
	if strings.Contains(strings.ToLower(cryptokms.BackendGoogleCloudKMS.String()), "backend") {
		t.Errorf("stringer did not strip backend prefix. missing -trimprefix=Backend?")
	}
	if cryptokms.Backend(0).String() != "Backend(0)" {
		t.Errorf("stringer invalid")
	}
}
