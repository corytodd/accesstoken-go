package accesstoken

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"testing"
)

const SECRET = "abvdefghijklmnopqrstuvwxyz01234567"

// Generate a token and verify the signature (HS256)
func TestJWTToken(t *testing.T) {

	token := New("accountSid", "apiKey", SECRET)

	token.Identity = "TestAccount"

	videoGrant := NewConversationsGrant("videoSid")
	token.AddGrant(videoGrant)

	sig, err := token.ToJWT(jwt.SigningMethodHS256)

	if err != nil {
		t.Errorf("token.ToJWT Failed: %v", err)
		t.Fail()
	}

	t.Logf("Token: %s", sig)

	// Parse the token.  Load the key from command line option
	parsed, err := jwt.Parse(sig, func(t *jwt.Token) (interface{}, error) {
		return []byte(SECRET), nil
	})

	// Print an error if we can't parse for some reason
	if err != nil {
		t.Errorf("Couldn't parse token: %v", err)
	}

	// Is token invalid?
	if !parsed.Valid {
		t.Errorf("Token is invalid")
	}

}

// Print a json object in accordance with the prophecy (or the command line options)
func printJSON(j interface{}) error {
	var out []byte
	var err error

	out, err = json.Marshal(j)

	if err == nil {
		fmt.Println(string(out))
	}

	return err
}
