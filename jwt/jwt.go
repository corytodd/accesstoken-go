package jwt

// JSON Web Token implementation
// Minimum implementation based on this spec:
// http://self-issued.info/docs/draft-jones-json-web-token-01.html
// follows the minimum design implemented in Twilio's Python accesstoken.jwt package

import (
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"log"

	_ "crypto/sha256" // Required for linking SHA256 to binary
	_ "crypto/sha512" // Required for linking SHA384 and SHA512 to binary
)

var (
	ErrUnsupportedAlgorithm         = errors.New("Algorithm not supported")
	ErrHashNotAvailable             = errors.New("The specified hash is not available")
	ErrSignatureVerificationFailure = errors.New("Signature verification failed")
	ErrInvalidSegmentEncoding       = errors.New("Invalid segment encoding")
	ErrNotEnoughSegments            = errors.New("Not enough segments")
	ErrTooManySegments              = errors.New("Too many segments")

	signingMethods = map[string]crypto.Hash{}
)

func init() {

	signingMethods["HS256"] = crypto.SHA256
	signingMethods["HS384"] = crypto.SHA384
	signingMethods["HS512"] = crypto.SHA512
}

// Encode creates a valid, signed JWT with the given payload and optional headers.
func Encode(payload map[string]interface{}, key string, algorithm string, customHeaders map[string]interface{}) (string, error) {

	alg, ok := signingMethods[algorithm]
	if !ok {
		return "", ErrUnsupportedAlgorithm
	}

	header := map[string]interface{}{
		"typ": "JWT",
		"alg": algorithm,
	}

	// Update map with any user-defined headers
	if customHeaders != nil {
		for k, v := range customHeaders {
			header[k] = v
		}
	}

	segments := []string{encodeSegment(header), encodeSegment(payload)}
	signMe := strings.Join(segments, ".")

	signature := signString(alg, signMe, []byte(key))

	segments = append(segments, encodeBase64Url(signature))
	token := strings.Join(segments, ".")

	log.Printf("token: %s", token)

	return token, nil

}

// Decode returns the payload portion of the JWT and optionally
// verifies the signature
func Decode(jwt string, key string, verify bool) interface{} {
	splits := strings.Split(jwt, ".")

	if len(splits) != 3 {
		if len(splits) < 3 {
			return ErrNotEnoughSegments
		} else {
			return ErrTooManySegments
		}
	}

	payloadRaw, err := decodeBase64Url(splits[1])
	if err != nil {
		return ErrInvalidSegmentEncoding
	}

	payload := jsonDumps(string(payloadRaw))

	if verify {
		if err := verifySignature(splits, []byte(key)); err != nil {
			return err
		}
	}

	return payload
}

// verifySignature returns nil or a specific error if the JWT signature is invalid
func verifySignature(segments []string, key []byte) error {

	b, err := decodeBase64Url(segments[0])
	if err != nil {
		return err
	}

	header := jsonDumps(string(b))
	algValue := header["alg"].(string)
	alg, ok := signingMethods[algValue]

	if !ok {
		return ErrUnsupportedAlgorithm
	}

	if !alg.Available() {
		return ErrHashNotAvailable
	}

	signaure, err := decodeBase64Url(segments[2])
	if err != nil {
		return err
	}

	// Symmetric keys, check if they match up
	hasher := hmac.New(alg.New, key)
	hasher.Write([]byte(segments[0] + "." + segments[1]))
	if !hmac.Equal(signaure, hasher.Sum(nil)) {
		return ErrSignatureVerificationFailure
	}
	return nil
}

// jsonDumps unmarshalls a given json string into an arbitrary map[string]interface{}
func jsonDumps(data string) map[string]interface{} {
	var arbitrary map[string]interface{}
	json.Unmarshal([]byte(data), &arbitrary)
	return arbitrary
}

// signString signs the given string using the provided hash function and key
func signString(hash crypto.Hash, msg string, key []byte) []byte {
	hasher := hmac.New(hash.New, key)
	hasher.Write([]byte(msg))

	return hasher.Sum(nil)
}

// encodeSegment returns the specified data as a base64 URL encoded string
func encodeSegment(data map[string]interface{}) string {
	b, _ := json.Marshal(data)
	return encodeBase64Url(b)
}

// encodeBase64Url returns data as base64 encoded URL with padding stripped
func encodeBase64Url(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

// decodeBase64Url returns the
func decodeBase64Url(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}
