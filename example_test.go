package tlslimit_test

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/shaj13/tlslimit"
)

func Example() {
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
