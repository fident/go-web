package gofidentweb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
)

/**
* Fident token helper methods
**/

const (
	fidentTokenName          = "fident-token"
	fidentTokenNameNonSecure = "fident-token-ns"
)

// TokenHelper instance for validating and reading fident tokens
type TokenHelper struct {
	aesKey       string
	rsaPublicKey rsa.PublicKey
}

// Attribute is a single user attribute
type Attribute struct {
	ID    string `json:"I"`
	Key   string `json:"K"`
	Value string `json:"V"`
}

// UserDetails is the decrypted user token taken from cookies with fident
type UserDetails struct {
	IdentityID         string      `json:"I"`
	Username           string      `json:"N"`
	Type               int8        `json:"T"`
	Attributes         []Attribute `json:"A"`
	Useragent          string      `json:"U"`
	MFA                bool        `json:"M"`
	Verified           bool        `json:"V"`
	decAttribFirstName string
	decAttribLastName  string
}

// GetFirstName returns the first name from tokens identity attributes
func (a *UserDetails) GetFirstName() string {
	if a.decAttribFirstName == "" {
		a.populateDecAttributes()
	}
	return a.decAttribFirstName
}

// GetLastName returns the last name from tokens identity attributes
func (a *UserDetails) GetLastName() string {
	if a.decAttribLastName == "" {
		a.populateDecAttributes()
	}
	return a.decAttribLastName
}

// GetEmailAddress returns email address for account
func (a *UserDetails) GetEmailAddress() string {
	return a.Username
}

// GetID returns identity ID for account
func (a *UserDetails) GetID() string {
	return a.IdentityID
}

func (a *UserDetails) populateDecAttributes() {
	for _, r := range a.Attributes {
		if r.Key == AttributeKeyFirstName {
			a.decAttribFirstName = r.Value
		}
		if r.Key == AttributeKeyLastName {
			a.decAttribLastName = r.Value
		}
	}
}

// NewTokenHelperWithRSAPub initialises the fident token helper with required crypto keys
func NewTokenHelperWithRSAPub(RSAPubKeyLocation string) (TokenHelper, error) {
	helper := TokenHelper{}
	keyData, err := ioutil.ReadFile(RSAPubKeyLocation)
	if err != nil {
		return helper, err
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return helper, err
	}

	helper.rsaPublicKey = *key
	return helper, nil
}

// NewTokenHelperWithAESAndRSAPub initialises the fident token package with required crypto keys
func NewTokenHelperWithAESAndRSAPub(AESKey, RSAPubKeyLocation string) (TokenHelper, error) {
	helper := TokenHelper{}
	helper.aesKey = AESKey
	keyData, err := ioutil.ReadFile(RSAPubKeyLocation)
	if err != nil {
		return helper, err
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return helper, err
	}
	helper.rsaPublicKey = *key
	return helper, nil
}

// NewTokenHelper initialises the fident token
func NewTokenHelper(AESKey string, RSAPubKey rsa.PublicKey) (TokenHelper, error) {
	helper := TokenHelper{}
	helper.aesKey = AESKey
	helper.rsaPublicKey = RSAPubKey
	return helper, nil
}

// VerifyToken verifies given token
func (t *TokenHelper) VerifyToken(tokenStr string) (UserDetails, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return &t.rsaPublicKey, nil
	})

	if err != nil || token.Valid == false {
		return UserDetails{}, errors.New("Invalid Token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return UserDetails{}, errors.New("Unable to map token claims")
	}

	payload, err := decryptPayload(t.aesKey, claims["payload"].(string))
	if err != nil {
		return UserDetails{}, err
	}

	var pl UserDetails
	err = json.Unmarshal(payload, &pl)
	if err != nil {
		return UserDetails{}, err
	}

	return pl, nil
}

// VerifyRequestToken verifies token for given request
func (t *TokenHelper) VerifyRequestToken(r *http.Request) (UserDetails, error) {
	tokenCookie, err := r.Cookie(fidentTokenName)
	if err != nil {
		if tokenCookie == nil {
			tokenCookie, err = r.Cookie(fidentTokenNameNonSecure)
			if err != nil {
				return UserDetails{}, errors.New("Invalid Token Cookie")
			}
		}
	}

	return t.VerifyToken(tokenCookie.Value)
}

func decryptPayload(keyin, tokenPayload string) ([]byte, error) {
	key := []byte(keyin)
	text, err := base64.StdEncoding.DecodeString(tokenPayload)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}

	return data, nil
}
