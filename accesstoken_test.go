package accesstoken

import (
	"github.com/corytodd/accesstoken-go/jwt"
	"testing"
)

const testSecret = "abvdefghijklmnopqrstuvwxyz01234567"

// Generate a token and verify the signature (HS256)
func TestJWTToken(t *testing.T) {

	token := New("accountSid", "apiKey", testSecret)

	token.Identity = "TestAccount"

	videoGrant := NewConversationsGrant("videoSid")
	token.AddGrant(videoGrant)

	signed, err := token.ToJWT(jwt.HS256)

	if err != nil {
		t.Errorf("token.ToJWT Failed: %v", err)
		t.Fail()
	}

	t.Logf("Token: %s", signed)

	// Parse the token.  Load the key from command line option
	parsed, err := jwt.Decode(signed, testSecret, true)

	// Print an error if we can't parse for some reason
	if err != nil {
		t.Errorf("Couldn't parse token: %v", err)
	}

	t.Logf("Parse: %s", parsed)

}
