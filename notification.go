package fident

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

/**
* Fident Notification handler
**/

const postDataField = "data"

const (
	jsonIDKey         = "ID"
	jsonUsernameKey   = "Username"
	jsonCreatedKey    = "Created"
	jsonAttributesKey = "Attributes"
	jsonSignatureKey  = "Signature"
	jsonTypeKey       = "Type"

	// AttributeKeyFirstName is the key for the first name user identity attribute
	attributeKeyFirstName = "firstname"

	// AttributeKeyLastName is the key for the last name user identity attribute
	attributeKeyLastName = "lastname"
)

// UserUpdatePayload is the serialisable structure for user updates
type UserUpdatePayload struct {
	ID          string             `json:"ID"`
	Username    string             `json:"Username"`
	Created     int64              `json:"Created"`
	Attributes  userAttributeSlice `json:"Attributes"`
	PayloadType int                `json:"Type"`
	Signature   string             `json:"Signature"`
}

// UserAttribute is the serialisable structure for user attributes
type UserAttribute struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

type userAttributeSlice []UserAttribute

// NotificationHandler is interface for notification update handler
type NotificationHandler func(update UserUpdatePayload)

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
	var payload UserUpdatePayload
	err := json.Unmarshal(p, &payload)
	if err == nil {
		if verifyNotification(payload) {
			if notificationHandler != nil {
				notificationHandler(payload)
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
func verifyNotification(n UserUpdatePayload) bool {
	sort.Sort(n.Attributes)
	attsig := ""
	for _, a := range n.Attributes {
		attsig += a.Key + a.Value
	}

	sigString := jsonAttributesKey + attsig + jsonCreatedKey + fmt.Sprintf("%d", n.Created) + jsonIDKey + n.ID + jsonTypeKey +
		fmt.Sprintf("%d", n.PayloadType) + jsonUsernameKey + n.Username

	return rsaVerify(sigString, n.Signature, &rsaPublicKey)
}

// NotificationFirstNameAttributeKey returns key for first name attribute
func NotificationFirstNameAttributeKey() string {
	return attributeKeyFirstName
}

// NotificationLastNameAttributeKey returns key for last name attribute
func NotificationLastNameAttributeKey() string {
	return attributeKeyLastName
}
