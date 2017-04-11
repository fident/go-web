package fident

import (
	"net/http"
	"net/http/httputil"
	"net/url"
)

/**
* Fident authset helper
* this helper allows fident to set an authtoken
* on your applications domain through the use of a reverse proxy
**/

// authsetterpath is a reference to fident's constant auth set path
const authsetterpath = "/as"

// StartAuthsetProxy starts auth setter proxy allowing
func StartAuthsetProxy(fidentTokenEndpoint string, server *http.ServeMux) error {
	remote, err := url.Parse(fidentTokenEndpoint)
	if err != nil {
		return err
	}
	proxy := httputil.NewSingleHostReverseProxy(remote)
	server.HandleFunc(authsetterpath, fidentTokenRProxy(proxy))
	return nil
}

// fidentTokenRProxy is reverse proxy for fident tokens
func fidentTokenRProxy(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		p.ServeHTTP(w, r)
	}
}
