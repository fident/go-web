package gofidentweb_test

import (
	"testing"

	gofidentweb "github.com/fident/go-web"
)

func TestGetVerifiedRegistrationURL(t *testing.T) {
	h, err := gofidentweb.InitURLHelper("http://my-great-app.net/", "http://localhost:8080/", "80211BZH0T2V1LBBZNXV")
	if err != nil {
		t.Errorf("Failed: %s\n", err.Error())
	}

	re, err := h.GetVerifiedRegistrationURL("johndoe@cubex.cloud")
	if err != nil {
		t.Errorf("Failed: %s\n", err.Error())
	}
	t.Log(re)
}
