package tlslimit

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/shaj13/libcache"
	"github.com/stretchr/testify/require"
)

func TestZeroLimiter(t *testing.T) {
	lim := new(Limiter)
	for i := 0; i < 100; i++ {
		err := lim.limit(new(tls.ClientHelloInfo))
		require.Error(t, err)
	}
}

func TestOption(t *testing.T) {
	table := []struct {
		opt    Option
		assert func(r *require.Assertions, l *Limiter)
	}{
		{
			opt: WithGetCertificate(func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil }),
			assert: func(r *require.Assertions, l *Limiter) {
				r.NotNil(l.getCertificate)
			},
		},
		{
			opt: WithGetConfigForClient(func(chi *tls.ClientHelloInfo) (*tls.Config, error) { return nil, nil }),
			assert: func(r *require.Assertions, l *Limiter) {
				r.NotNil(l.getConfigForClient)
			},
		},
		{
			opt: WithLimit(time.Second),
			assert: func(r *require.Assertions, l *Limiter) {
				r.Equal(l.r, time.Second)
			},
		},
		{
			opt: WithBursts(100),
			assert: func(r *require.Assertions, l *Limiter) {
				r.Equal(l.b, 100)
			},
		},
		{
			opt: WithTLSHostname(),
			assert: func(r *require.Assertions, l *Limiter) {
				r.NotNil(l.keyFn)
			},
		},
		{
			opt: WithTLSClientIP(),
			assert: func(r *require.Assertions, l *Limiter) {
				r.NotNil(l.keyFn)
			},
		},
		{
			opt: WithCacheMaxSize(100),
			assert: func(r *require.Assertions, l *Limiter) {
				r.NotNil(l.cache)
				r.Equal(l.cache.Cap(), 100)
			},
		},
	}

	for _, tt := range table {
		lim := NewLimiter(tt.opt)
		r := require.New(t)
		tt.assert(r, lim)
	}
}

func TestLimiterGet(t *testing.T) {
	tests := []struct {
		getCertificate     func(*tls.ClientHelloInfo) (*tls.Certificate, error)
		getConfigForClient func(*tls.ClientHelloInfo) (*tls.Config, error)
		runGetCertificate  bool
		expectErr          bool
	}{
		{
			runGetCertificate: true,
		},
		{
			runGetCertificate: true,
			expectErr:         true,
			getCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return nil, fmt.Errorf("")
			},
		},
		{
			runGetCertificate: true,
			getCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return nil, nil
			},
		},
		{
			runGetCertificate: false,
		},
		{
			expectErr: true,
			getConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
				return nil, fmt.Errorf("")
			},
		},
		{
			getConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
				return nil, nil
			},
		},
	}

	for _, tt := range tests {
		lim := NewLimiter(
			WithLimit(1),
			WithBursts(1),
			WithGetCertificate(tt.getCertificate),
			WithGetConfigForClient(tt.getConfigForClient),
		)

		var err error

		ci := new(tls.ClientHelloInfo)

		if tt.runGetCertificate {
			_, err = lim.GetCertificate(ci)
		} else {
			_, err = lim.GetConfigForClient(ci)
		}

		require.Equal(t, tt.expectErr, err != nil)
	}
}

func TestLimiterLimit(t *testing.T) {
	tests := []struct {
		lim       *Limiter
		expectErr bool
	}{
		{
			lim:       new(Limiter),
			expectErr: true,
		},
		{
			lim: &Limiter{
				cache: libcache.LRU.New(0),
			},
			expectErr: true,
		},
		{
			lim: &Limiter{
				cache: libcache.LRU.New(0),
				r:     time.Second,
			},
			expectErr: true,
		},
		{
			lim: &Limiter{
				cache: libcache.LRU.New(0),
				keyFn: func(chi *tls.ClientHelloInfo) string { return "" },
				r:     time.Second,
				b:     1,
			},
		},
	}

	for _, tt := range tests {
		ci := new(tls.ClientHelloInfo)
		err := tt.lim.limit(ci)
		require.Equal(t, tt.expectErr, err != nil)
	}
}

var ecdsaCertPEM = `-----BEGIN CERTIFICATE-----
MIIB/jCCAWICCQDscdUxw16XFDAJBgcqhkjOPQQBMEUxCzAJBgNVBAYTAkFVMRMw
EQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0
eSBMdGQwHhcNMTIxMTE0MTI0MDQ4WhcNMTUxMTE0MTI0MDQ4WjBFMQswCQYDVQQG
EwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lk
Z2l0cyBQdHkgTHRkMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBY9+my9OoeSUR
lDQdV/x8LsOuLilthhiS1Tz4aGDHIPwC1mlvnf7fg5lecYpMCrLLhauAc1UJXcgl
01xoLuzgtAEAgv2P/jgytzRSpUYvgLBt1UA0leLYBy6mQQbrNEuqT3INapKIcUv8
XxYP0xMEUksLPq6Ca+CRSqTtrd/23uTnapkwCQYHKoZIzj0EAQOBigAwgYYCQXJo
A7Sl2nLVf+4Iu/tAX/IF4MavARKC4PPHK3zfuGfPR3oCCcsAoz3kAzOeijvd0iXb
H5jBImIxPL4WxQNiBTexAkF8D1EtpYuWdlVQ80/h/f4pBcGiXPqX5h2PQSQY7hP1
+jwM1FGS4fREIOvlBYr/SzzQRtwrvrzGYxDEDbsC0ZGRnA==
-----END CERTIFICATE-----
`

var ecdsaKeyPEM = `-----BEGIN EC PARAMETERS-----
BgUrgQQAIw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBrsoKp0oqcv6/JovJJDoDVSGWdirrkgCWxrprGlzB9o0X8fV675X0
NwuBenXFfeZvVcwluO7/Q9wkYoPd/t3jGImgBwYFK4EEACOhgYkDgYYABAFj36bL
06h5JRGUNB1X/Hwuw64uKW2GGJLVPPhoYMcg/ALWaW+d/t+DmV5xikwKssuFq4Bz
VQldyCXTXGgu7OC0AQCC/Y/+ODK3NFKlRi+AsG3VQDSV4tgHLqZBBus0S6pPcg1q
kohxS/xfFg/TEwRSSws+roJr4JFKpO2t3/be5OdqmQ==
-----END EC PRIVATE KEY-----
`

func TestEverything(t *testing.T) {
	lim := NewLimiter(
		WithLimit(time.Second),
		WithBursts(10),
		WithGetCertificate(func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := tls.X509KeyPair([]byte(ecdsaCertPEM), []byte(ecdsaKeyPEM))
			if err != nil {
				return nil, err
			}
			return &cert, nil
		}),
		WithTLSClientIP(),
	)

	srv := &http.Server{
		Addr: "127.0.0.1:8080",
		TLSConfig: &tls.Config{
			GetCertificate: lim.GetCertificate,
		},
	}
	defer srv.Close()

	url := "https://" + srv.Addr

	go func() {
		err := srv.ListenAndServeTLS("", "")
		if err != http.ErrServerClosed {
			require.NoError(t, err)
		}
	}()

	newClient := func() *http.Client {
		return &http.Client{
			Transport: &http.Transport{
				ForceAttemptHTTP2: true,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
	}

	advance := func(c *http.Client, max int) {
		ok := c != nil
		for i := 0; i < max; i++ {
			if !ok {
				c = newClient()
			}
			_, err := c.Get(url)
			require.NoError(t, err, i)
		}
	}

	// Wait for server to be up and live.
	for i := 0; i < 10; i++ {
		conn, err := net.DialTimeout("tcp", srv.Addr, time.Second)
		if err == nil {
			conn.Close()
			break
		}

		time.Sleep(time.Millisecond * 500)
	}

	// Round #1 TLS handshakes limit exceeded.
	advance(nil, 10)
	c := newClient()
	_, err := c.Get(url)
	require.Error(t, err)

	// Round #2 TLS session resumption is used the rate limiting will not be applied.
	lim.cache.Purge()
	c = newClient()
	advance(c, 100)
}
