# go-web
Go SDK for Fident web projects

```go
import gofidentweb "github.com/fident/go-web"
```

---
#### Token Helper
Helper library for decoding data from fident authtokens
```go
gofidentweb.InitTokenHelperWithAESAndRSAPub(AESKey,RSAPemLocation)

// Can then call this method to get the currently logged in user
func VerifyRequestToken(r *http.Request) (UserDetails, error)
```

---
#### URL Helper
Generates fident URLS that you can send users to for actions such as login,logout and registration. Generally these actions will direct back to your domain on completion.
```go
// Init the URL helper, set 'fidentRegistrationSecret' to "" if you don't plan on using pre-registered verified registration URLs
gofidentweb.InitURLHelper(productServiceURL, fidentServiceURL, fidentRegistrationSecret)

// Actions now available such as the method below
func GetLoginURL() string 
```

---
#### Notification endpoint helper
Helper sets up your endpoint for recieving notifications when users change their details in Fident
```go
// Notificationendpoint (registered with fident)
gofidentweb.InitWithRSAPub(pathToFidentPublicKey)
gofidentweb.SetNotificationHandler(fidentNotificationHandler)
server.HandleFunc(NotificationEndpoint, gofidentweb.NotificationEndpoint)

// The following method would be called with a user update notification payload
func fidentNotificationHandler(payload fident.UserUpdatePayload) {
```

---
#### Authset helper
Helper sets auth on your products domain
```go
gofidentweb.StartAuthsetProxy(fidentTokenEndpoint, server)
```
