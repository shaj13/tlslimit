[![PkgGoDev](https://pkg.go.dev/badge/github.com/shaj13/tlslimit)](https://pkg.go.dev/github.com/shaj13/tlslimit)
[![Go Report Card](https://goreportcard.com/badge/github.com/shaj13/tlslimit)](https://goreportcard.com/report/github.com/shaj13/tlslimit)
[![Coverage Status](https://coveralls.io/repos/github/shaj13/tlslimit/badge.svg?branch=main)](https://coveralls.io/github/shaj13/tlslimit?branch=main)
[![CircleCI](https://circleci.com/gh/shaj13/tlslimit/tree/main.svg?style=svg)](https://circleci.com/gh/shaj13/env/tree/main)

# TLSLimit
Limiting the rate of TLS handshakes.

## Motivation
When a client send a request, the server must invest some of its precious CPU cycles into responding to that client, In the case of a secured request, the investment is substantial because of the involved cryptography in TLS handshakes. 

Application layer rate limits would not prevent CPU overload because they work after TLS termination, same for [limiting the number of simultaneous connections](https://pkg.go.dev/golang.org/x/net/netutil) because the attacker or user can keep sending new requests using new connections that trigger TLS handshakes again and again.

For example see gitlab production [incident](https://gitlab.com/gitlab-com/gl-infra/production/-/issues/6769) caused by TLS handshakes.

TLSLimit is here to help with that, It provides a rate limiter to fewer expensive TLS handshakes, mitigates SSL/TLS exhaustion DDoS attacks, and an overall reduction in required server resources without affecting the overall number of concurrent requests that the server can handle.

## Installation 
Using tlslimit is easy. First, use go get to install the latest version of the library.

```sh
go get github.com/shaj13/tlslimit
```
Next, include tlslimit in your application:
```go
import (
    "github.com/shaj13/tlslimit"
)
```

## Usage
```go
package main

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/shaj13/tlslimit"
)

func main() {
	// Declare the actual callbacks to retrieve the server certificate
	// you don't need both callbacks, choose the one that suits your application needs.
	//
	// Most callers prefer the GetCertificate.

	getCert := func(ci *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// Return actual certificate.
		return nil, nil
	}

	getConfig := func(ci *tls.ClientHelloInfo) (*tls.Config, error) {
		// Return actual config.
		return nil, nil
	}

	// Define a Limiter to enforce TLS rate limiting.
	// To prevent a client from exhausting application resources
	// and mitigates SSL/TLS exhaustion DDoS attacks.
	//
	// For Example Allow 20 TLS handshakes per minute for each client IP.
	lim := tlslimit.NewLimiter(
		tlslimit.WithBursts(20),
		tlslimit.WithLimit(time.Minute),
		tlslimit.WithTLSClientIP(),
		// Use WithGetCertificate or WithGetConfigForClient
		tlslimit.WithGetCertificate(getCert),
		tlslimit.WithGetConfigForClient(getConfig),
	)

	// Tie the Limiter to the tls.Config.
	cfg := &tls.Config{
		// Use GetCertificate or GetConfigForClient
		GetCertificate:     lim.GetCertificate,
		GetConfigForClient: lim.GetConfigForClient,
		MinVersion:         tls.VersionTLS13,
	}

	srv := http.Server{
		TLSConfig: cfg,
	}

	_ = srv.ListenAndServeTLS("", "")
}
```

# Contributing
1. Fork it
2. Download your fork to your PC (`git clone https://github.com/your_username/tlslimit && cd env`)
3. Create your feature branch (`git checkout -b my-new-feature`)
4. Make changes and add them (`git add .`)
5. Commit your changes (`git commit -m 'Add some feature'`)
6. Push to the branch (`git push origin my-new-feature`)
7. Create new pull request

# License
tlslimit is released under the MIT license. See [LICENSE](https://github.com/shaj13/tlslimit/blob/main/LICENSE)
