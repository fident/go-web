package gofidentweb_test

import (
	"testing"

	"github.com/fident/gofidentweb"
)

const (
	FNK = "A"
	LNK = "B"
)

func TestUserDetailDecAttrib(t *testing.T) {
	a := []gofidentweb.Attribute{}

	a = append(a, gofidentweb.Attribute{
		Key:   gofidentweb.AttributeKeyFirstNameKey,
		Value: FNK,
	})

	a = append(a, gofidentweb.Attribute{
		Key:   gofidentweb.AttributeKeyLastNameKey,
		Value: LNK,
	})

	u := gofidentweb.UserDetails{Attributes: a}

	if u.GetFirstName() != FNK {
		t.Errorf("Failed: firstname value `%s` was not expected\n", u.GetFirstName())
	}

	if u.GetLastName() != LNK {
		t.Errorf("Failed: lastname value `%s` was not expected\n", u.GetLastName())
	}
}
