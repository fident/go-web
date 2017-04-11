# gofidentweb
Go SDK for Fident web projects

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
gofidentweb.InitURLHelper(productURL, fidentServiceURL)
```

---
#### Notification endpoint helper
Helper sets up your endpoint for recieving notifications when users change their details in Fident
```go
// Notificationendpoint (registered with fident)
gofidentweb.SetNotificationHandler(fidentNotificationHandler)
server.HandleFunc(NotificationEndpoint, gofidentweb.NotificationEndpoint)
```

---
#### Authset helper
Helper sets auth on your products domain
```go
gofidentweb.StartAuthsetProxy(fidentTokenEndpoint, server)
```