package gofidentweb

import (
	"fmt"
)

/**
* Fident URL helper methods
**/

const (
	fidentDestinationParam     = "destination"
	fidentLoginEndpoint        = "/login"
	fidentLogoutEndpoint       = "/logout"
	fidentRegistrationEndpoint = "/register"
)

var (
	nProductServiceEndpoint = ""
	nFidentServiceEndpoint  = ""
)

// InitURLHelper inits the fident URL helper
func InitURLHelper(productServiceURL, fidentServiceURL string) error {
	nProductServiceEndpoint = productServiceURL
	nFidentServiceEndpoint = fidentServiceURL
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
