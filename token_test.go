package gofidentweb_test

import (
	"testing"

	gofidentweb "github.com/fident/go-web"
)

const (
	FNK = "A"
	LNK = "B"
)

func TestUserDetailDecAttrib(t *testing.T) {
	a := []gofidentweb.Attribute{}

	a = append(a, gofidentweb.Attribute{
		Key:   gofidentweb.AttributeKeyFirstName,
		Value: FNK,
	})

	a = append(a, gofidentweb.Attribute{
		Key:   gofidentweb.AttributeKeyLastName,
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
