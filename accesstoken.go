package accesstoken

import (
	"fmt"
	"github.com/corytodd/accesstoken-go/jwt"
	"time"
)

// DefaultAlgorithm is your preferred signing algorithm
var DefaultAlgorithm = "HS256"

// AccessToken is a JWT that grants access to Twilio services
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
func (t *AccessToken) ToJWT(algorithm string) (string, error) {

	if algorithm == "" {
		algorithm = DefaultAlgorithm
	}

	header := map[string]interface{}{
		"typ": "JWT",
		"cty": "twilio-fpa;v=1",
	}

	now := time.Now().UTC().Unix()
	payload := map[string]interface{}{}

	payload["jti"] = fmt.Sprintf("%s-%d", t.apiKey, now)
	payload["iss"] = t.apiKey
	payload["sub"] = t.accountSid
	payload["exp"] = now + t.ttl

	if len(t.grants) > 0 {

		payload["grants"] = map[string]interface{}{}

		if len(t.Identity) > 0 {
			payload["grants"].(map[string]interface{})["identity"] = t.Identity
		}

		for _, grant := range t.grants {
			payload["grants"].(map[string]interface{})[grant.key()] = grant.ToPayload()
		}

	}

	if len(t.nbf) > 0 {
		payload["nbf"] = t.nbf
	}

	//Sign and return the AccessToken
	return jwt.Encode(payload, header, t.apiSecret, "HS256")
}
