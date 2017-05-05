package gofidentweb_test

import (
	"testing"

	"github.com/fident/gofidentweb"
)

func TestGetVerifiedRegistrationURL(t *testing.T) {
	err := gofidentweb.InitURLHelper("http://my-great-app.net/", "http://localhost:8080/", "80211BZH0T2V1LBBZNXV")
	if err != nil {
		t.Errorf("Failed: %s\n", err.Error())
	}

	re, err := gofidentweb.GetVerifiedRegistrationURL("johndoe@cubex.cloud")
	if err != nil {
		t.Errorf("Failed: %s\n", err.Error())
	}
	t.Log(re)
}
