package main

import (
	"fmt"
	"net/http"

	gofidentweb "github.com/fident/go-web"
	cli "gopkg.in/alecthomas/kingpin.v2"
)

const (
	productionFidentTokenEndpoint = "https://authsetter.fident.io"
	localFidentTokenEndpoint      = "http://localhost:7181"

	serviceName    = "authsetter proxy"
	serviceVersion = "1.0.0"
)

var (
	fidentTokenEndpoint = cli.Flag("token-endpoint", "Set Fident token endpoint.").Default(productionFidentTokenEndpoint).Short('t').String()
	devmode             = cli.Flag("dev", "Enable developer Mode.").Default("false").Short('d').Bool()
)

func main() {
	cli.Version(serviceVersion)
	cli.Parse()

	server := http.NewServeMux()

	ep := *fidentTokenEndpoint
	b := ":80"
	if *devmode {
		ep = localFidentTokenEndpoint
		b = ":8088"
	}

	fmt.Printf("Starting %s\nlistening on %s\n", serviceName, b)

	gofidentweb.StartAuthsetProxy(ep, server)

	err := http.ListenAndServe(b, server)
	if err != nil {
		fmt.Printf("Error when starting web listener %s\n", err.Error())
	}
}
