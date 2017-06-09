package gofidentweb

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
)

/**
* Fident URL helper methods
**/

const (
	fidentDestinationParam         = "destination"
	fidentRegEmailParam            = "email"
	fidentSigParm                  = "presig"
	fidentLoginEndpoint            = "/login"
	fidentLogoutEndpoint           = "/logout"
	fidentRegistrationEndpoint     = "/register"
	fidentPostRegistrationEndpoint = "/post-register"
)

var (
	nProductServiceEndpoint   = ""
	nFidentServiceEndpoint    = ""
	nFidentRegistrationSecret = ""
)

// InitURLHelper inits the fident URL helper, set fidentRegistrationSecret to "" if you don't plan on using verified registration URLs
func InitURLHelper(productServiceURL, fidentServiceURL, fidentRegistrationSecret string) error {
	nProductServiceEndpoint = productServiceURL
	nFidentServiceEndpoint = fidentServiceURL
	nFidentRegistrationSecret = fidentRegistrationSecret
	return nil
}

// GetLoginURL get fident login URL that redirects back to project on login
func GetLoginURL() string {
	return fmt.Sprintf("%s%s?%s=%s", nFidentServiceEndpoint, fidentLoginEndpoint, fidentDestinationParam, nProductServiceEndpoint)
}

// GetLogoutURL get fident logout URL that redirects back to project on logout
func GetLogoutURL() string {
	return fmt.Sprintf("%s%s?%s=%s", nFidentServiceEndpoint, fidentLogoutEndpoint, fidentDestinationParam, nProductServiceEndpoint)
}

// GetRegistrationURL get fident registration URL that redirects back to project after registration
func GetRegistrationURL() string {
	return fmt.Sprintf("%s%s?%s=%s", nFidentServiceEndpoint, fidentRegistrationEndpoint, fidentDestinationParam, nProductServiceEndpoint)
}

// GetRegistrationPostURL get fident registration form POST URL that redirects back to project after registration & login : use key 'email'
func GetRegistrationPostURL() string {
	return fmt.Sprintf("%s%s?%s=%s", nFidentServiceEndpoint, fidentPostRegistrationEndpoint, fidentDestinationParam, nProductServiceEndpoint)
}

// GetVerifiedRegistrationURL get fident registration URL where your app has already verified the email address
func GetVerifiedRegistrationURL(email string) (string, error) {
	if nFidentRegistrationSecret == "" {
		return "", errors.New("HMAC secret has not been set")
	}

	u, err := url.Parse(fmt.Sprintf("%s%s", nFidentServiceEndpoint, fidentRegistrationEndpoint))
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Set(fidentDestinationParam, nProductServiceEndpoint)
	q.Set(fidentRegEmailParam, email)

	s := []byte(nFidentRegistrationSecret)
	h := hmac.New(sha256.New, s)
	h.Write([]byte(email))
	r := hex.EncodeToString(h.Sum(nil))

	q.Set(fidentSigParm, r)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
