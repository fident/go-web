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
	fidentManagementEndpoint       = "/user-management"
	fidentRegistrationEndpoint     = "/register"
	fidentPostRegistrationEndpoint = "/post-register"
)

// URLHelper is a fident URL helper instance
type URLHelper struct {
	nProductServiceEndpoint, nFidentServiceEndpoint, nFidentRegistrationSecret string
}

// InitURLHelper inits the fident URL helper, set fidentRegistrationSecret to "" if you don't plan on using verified registration URLs
func InitURLHelper(productServiceURL, fidentServiceURL, fidentRegistrationSecret string) (URLHelper, error) {
	return URLHelper{
		nProductServiceEndpoint:   productServiceURL,
		nFidentServiceEndpoint:    fidentServiceURL,
		nFidentRegistrationSecret: fidentRegistrationSecret,
	}, nil
}

// GetLoginURL get fident login URL that redirects back to project on login
func (n *URLHelper) GetLoginURL() string {
	return fmt.Sprintf("%s%s?%s=%s", n.nFidentServiceEndpoint, fidentLoginEndpoint, fidentDestinationParam, n.nProductServiceEndpoint)
}

// GetManagementURL get fident account management URL for current user
func (n *URLHelper) GetManagementURL() string {
	return fmt.Sprintf("%s%s?%s=%s", n.nFidentServiceEndpoint, fidentManagementEndpoint, fidentDestinationParam, n.nProductServiceEndpoint)
}

// GetLogoutURL get fident logout URL that redirects back to project on logout
func (n *URLHelper) GetLogoutURL() string {
	return fmt.Sprintf("%s%s?%s=%s", n.nFidentServiceEndpoint, fidentLogoutEndpoint, fidentDestinationParam, n.nProductServiceEndpoint)
}

// GetRegistrationURL get fident registration URL that redirects back to project after registration
func (n *URLHelper) GetRegistrationURL() string {
	return fmt.Sprintf("%s%s?%s=%s", n.nFidentServiceEndpoint, fidentRegistrationEndpoint, fidentDestinationParam, n.nProductServiceEndpoint)
}

// GetRegistrationPostURL get fident registration form POST URL that redirects back to project after registration & login : use key 'email'
func (n *URLHelper) GetRegistrationPostURL() string {
	return fmt.Sprintf("%s%s?%s=%s", n.nFidentServiceEndpoint, fidentPostRegistrationEndpoint, fidentDestinationParam, n.nProductServiceEndpoint)
}

// GetVerifiedRegistrationURL get fident registration URL where your app has already verified the email address
func (n *URLHelper) GetVerifiedRegistrationURL(email string) (string, error) {
	if n.nFidentRegistrationSecret == "" {
		return "", errors.New("HMAC secret has not been set")
	}

	u, err := url.Parse(fmt.Sprintf("%s%s", n.nFidentServiceEndpoint, fidentRegistrationEndpoint))
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Set(fidentDestinationParam, n.nProductServiceEndpoint)
	q.Set(fidentRegEmailParam, email)

	s := []byte(n.nFidentRegistrationSecret)
	h := hmac.New(sha256.New, s)
	h.Write([]byte(email))
	r := hex.EncodeToString(h.Sum(nil))

	q.Set(fidentSigParm, r)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
