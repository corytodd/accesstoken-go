package accesstoken

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"time"
)

// Change this to your preferred signing algorithm
var DEFAULT_ALGORITHM = jwt.SigningMethodHS256

// A Twilio AccessToken
type AccessToken struct {
	accountSid string // SID from here: https://www.twilio.com/user/account/settings
	apiKey     string // Generated here: https://www.twilio.com/user/account/video/dev-tools/api-keys
	apiSecret  string // Generated here: https://www.twilio.com/user/account/video/dev-tools/api-keys

	// Default: ""
	Identity string // Generated here: https://www.twilio.com/user/account/video/profiles

	// Default: 3600
	ttl int64 // Must be a UTC timestamp

	// Default: unset
	nbf string // Not before time: current date/time must be after this time

	grants []Grant // Slice of grants attached to this
}

// Create a new AccessToken
func New(accountSid, apiKey, apiSecret string) *AccessToken {

	var grants []Grant
	return &AccessToken{
		accountSid: accountSid,
		apiKey:     apiKey,
		apiSecret:  apiSecret,
		ttl:        3600,
		grants:     grants,
	}

}

// Attach a grant to this AccessToken
func (t *AccessToken) AddGrant(grant Grant) {
	t.grants = append(t.grants, grant)
}

// Ported from: https://github.com/twilio/twilio-python/blob/master/twilio/access_token.py
// Returns the signed JWT or an error
func (t *AccessToken) ToJWT(algorithm jwt.SigningMethod) (string, error) {

	if algorithm == nil {
		algorithm = DEFAULT_ALGORITHM
	}

	token := jwt.New(algorithm)

	token.Header["typ"] = "JWT"
	token.Header["cty"] = "twilio-fpa;v=1"

	if len(t.grants) > 0 {

		token.Claims["grants"] = map[string]interface{}{}

		if len(t.Identity) > 0 {
			token.Claims["grants"].(map[string]interface{})["identity"] = t.Identity
		}

		for _, grant := range t.grants {
			token.Claims["grants"].(map[string]interface{})[grant.key()] = grant.ToPayload()
		}

	}

	now := time.Now().UTC().Unix()

	token.Claims["jti"] = fmt.Sprintf("%s-%d", t.apiKey, now)
	token.Claims["iss"] = t.apiKey
	token.Claims["sub"] = t.accountSid
	token.Claims["exp"] = now + t.ttl

	if len(t.nbf) > 0 {
		token.Claims["nbf"] = t.nbf
	}

	//Sign and return the AccessToken
	return token.SignedString([]byte(t.apiSecret))
}
