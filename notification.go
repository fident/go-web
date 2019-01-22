package gofidentweb

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

/**
* Fident Notification handler
**/
const (
	// JSONIDKey is the key used for ID
	JSONIDKey = "ID"

	// JSONUsernameKey is the key used for username
	JSONUsernameKey = "Username"

	// JSONCreatedKey is the key used for created epoch
	JSONCreatedKey = "Created"

	// JSONAttributesKey is the key used for identity attributes
	JSONAttributesKey = "Attributes"

	// JSONSignatureKey is the key used for fident signature
	JSONSignatureKey = "Signature"

	// JSONTypeKey is the key used for identity type
	JSONTypeKey = "Type"

	// ConfirmationResponse is the response body from sucessful requests to
	ConfirmationResponse = "con"
)

// SignedPayload is a signed fident payload, signature should match data
type SignedPayload struct {
	Data        string `json:"data"`
	PayloadType int64  `json:"data_type"`
	Signature   string `json:"signature"`
}

// UserUpdatePayload is the serialisable structure for user updates
type UserUpdatePayload struct {
	ID         string             `json:"ID"`
	Username   string             `json:"Username"`
	Created    int64              `json:"Created"`
	Attributes userAttributeSlice `json:"Attributes"`
}

// UserAttribute is the serialisable structure for user attributes
type UserAttribute struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

var notificationTokenHelper TokenHelper

// SetNotificationTokenHelper sets the token helper used by notification endpoints
func SetNotificationTokenHelper(t TokenHelper) {
	notificationTokenHelper = t
}

// GetFirstNameAttribute returns the first name from account detail attributes
func (a *UserUpdatePayload) GetFirstNameAttribute() string {
	for _, r := range a.Attributes {
		if r.Key == AttributeKeyFirstNameKey {
			return r.Value
		}
	}
	return ""
}

// GetLastNameAttribute returns the last name from account detail attributes
func (a *UserUpdatePayload) GetLastNameAttribute() string {
	for _, r := range a.Attributes {
		if r.Key == AttributeKeyLastNameKey {
			return r.Value
		}
	}
	return ""
}

// GetEmailAddress returns email address for account
func (a *UserUpdatePayload) GetEmailAddress() string {
	return a.Username
}

type userAttributeSlice []UserAttribute

// NotificationHandler is interface for notification update handler
type NotificationHandler func(update UserUpdatePayload) bool

func (d userAttributeSlice) Len() int { return len(d) }

func (d userAttributeSlice) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}

func (d userAttributeSlice) Less(i, j int) bool {
	si := d[i].Key
	sj := d[j].Key
	silow := strings.ToLower(si)
	sjlow := strings.ToLower(sj)
	if silow == sjlow {
		return si < sj
	}
	return silow < sjlow
}

var notificationHandler NotificationHandler

// SetNotificationHandler sets reference to your applications fident notification handler
func SetNotificationHandler(handler NotificationHandler) {
	notificationHandler = handler
}

// NotificationEndpoint handles notifications from fident for events such as user updates
func NotificationEndpoint(rw http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.NotFound(rw, req)
	}
	p := make([]byte, req.ContentLength)
	req.Body.Read(p)
	var payload SignedPayload
	err := json.Unmarshal(p, &payload)
	if err == nil {
		if verifyNotification(payload) {
			if notificationHandler != nil {
				var pl UserUpdatePayload
				err := json.Unmarshal([]byte(payload.Data), &pl)
				if err != nil {
					http.NotFound(rw, req)
				}
				if notificationHandler(pl) {
					rw.Write([]byte(ConfirmationResponse))
				}
			} else {
				fmt.Printf("Fident notification helper: Recieved notification but notificationHandler has not been set")
			}
		} else {
			fmt.Printf("Fident notification helper: Recieved unsigned notification")
		}
	}
}

// rsaVerify message signature with public key
func rsaVerify(data, signature string, pubkey *rsa.PublicKey) bool {
	rawSignature, err := base64.URLEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	hash := sha256.New()
	hash.Write([]byte(data))
	hashresult := hash.Sum(nil)
	result := rsa.VerifyPKCS1v15(pubkey, crypto.SHA256, hashresult, rawSignature)
	if result == nil {
		return true
	}
	return false
}

// verifies notification payload originates from Fident
func verifyNotification(n SignedPayload) bool {
	return rsaVerify(n.Data, n.Signature, &notificationTokenHelper.rsaPublicKey)
}

// NotificationFirstNameAttributeKey returns key for first name attribute
func NotificationFirstNameAttributeKey() string {
	return AttributeKeyFirstNameKey
}

// NotificationLastNameAttributeKey returns key for last name attribute
func NotificationLastNameAttributeKey() string {
	return AttributeKeyLastNameKey
}
