package fident

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

var (
	aesKey       = ""
	rsaPublicKey rsa.PublicKey
)

type attribute struct {
	ID    string `json:"I"`
	Key   string `json:"K"`
	Value string `json:"V"`
}

// UserDetails is the decrypted user token taken from cookies with fident
type UserDetails struct {
	IdentityID string      `json:"I"`
	Username   string      `json:"N"`
	Type       int8        `json:"T"`
	Attributes []attribute `json:"A"`
	Useragent  string      `json:"U"`
}

// InitTokenHelperWithAESAndRSAPub initialises the fident token package with required crypto keys
func InitTokenHelperWithAESAndRSAPub(AESKey, RSAPubKeyLocation string) error {
	aesKey = AESKey
	keyData, err := ioutil.ReadFile(RSAPubKeyLocation)
	if err != nil {
		return err
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return err
	}
	rsaPublicKey = *key
	return nil
}

// VerifyRequestToken verifies token for given request
func VerifyRequestToken(r *http.Request) (UserDetails, error) {
	tokenCookie, err := r.Cookie(fidentTokenName)
	if err != nil {
		if tokenCookie == nil {
			tokenCookie, err = r.Cookie(fidentTokenNameNonSecure)
			if err != nil {
				return UserDetails{}, errors.New("Invalid Token Cookie")
			}
		}
	}

	token, err := jwt.Parse(tokenCookie.Value, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return &rsaPublicKey, nil
	})

	if err != nil || token.Valid == false {
		return UserDetails{}, errors.New("Invalid Token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return UserDetails{}, errors.New("Unable to map token claims")
	}

	payload, err := decryptPortcullisPayload(aesKey, claims["payload"].(string))
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

func decryptPortcullisPayload(keyin, tokenPayload string) ([]byte, error) {
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
