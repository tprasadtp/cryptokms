// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package shared_test

import (
	"encoding/base64"
	"testing"

	"github.com/tprasadtp/cryptokms/internal/shared"
	"github.com/tprasadtp/cryptokms/internal/testkeys"
)

func TestEncodeBase64(t *testing.T) {
	input := shared.MustMarshalPrivateKey(testkeys.GetRSA2048PrivateKey())
	b64Input := shared.EncodeBase64(input)

	b64Decode := make([]byte, base64.StdEncoding.DecodedLen(len(b64Input)))
	_, err := base64.StdEncoding.Decode(b64Decode, b64Input)
	if err != nil {
		t.Errorf("failed to decode: %s", err)
	}
}
