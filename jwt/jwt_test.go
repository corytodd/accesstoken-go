package jwt

import (
	"fmt"
	"testing"
)

const Secret = "abvdefghijklmnopqrstuvwxyz01234567"

// Generate a token and verify the signature (HS256)
func TestEncode(t *testing.T) {

	headers := map[string]interface{}{
		"cty": "twilio-fpa;v=1",
	}

	payload := map[string]interface{}{
		"jti": fmt.Sprintf("%s-%s", "someissuer", "1450900077"),
		"iss": "someissuer",
		"sub": "somethingsid",
		"exp": "1450900077",
	}

	sig, err := Encode(payload, headers, Secret, HS256)

	if err != nil {

		t.Errorf("Couldn't encode: %v", err)
		t.Fail()

	} else {
		t.Logf("Token: %s", sig)
	}

	decoded, err := Decode(sig, Secret, true)

	if err != nil {
		t.Errorf("Failed to decode: %v", err)
		t.Fail()
	}

	t.Logf("Decoded: %v", decoded)

}
