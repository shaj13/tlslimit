package tlslimit

import (
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/shaj13/libcache"
	_ "github.com/shaj13/libcache/lru"
	"golang.org/x/time/rate"
)

// Option configures Limiter using the functional options paradigm
// popularized by Rob Pike and Dave Cheney. If you're unfamiliar with this style,
// see https://commandcenter.blogspot.com/2014/01/self-referential-functions-and-design.html and
// https://dave.cheney.net/2014/10/17/functional-options-for-friendly-apis.
type Option interface {
	apply(*Limiter)
}

// OptionFunc implements Option interface.
type optionFunc func(*Limiter)

// apply the configuration to the provided config.
func (fn optionFunc) apply(r *Limiter) {
	fn(r)
}

// WithGetCertificate returns a tls.Certificate based on the given
// tls.ClientHelloInfo. It will only be called if the Limiter.GetCertificate
// sat in tls.Config and client TLS handshakes rate limit does not exceeded.
//
// If fn is nil or returns nil, then the TLS handshakes will be aborted.
func WithGetCertificate(fn func(*tls.ClientHelloInfo) (*tls.Certificate, error)) Option {
	return optionFunc(func(l *Limiter) {
		l.getCertificate = fn
	})
}

// WithGetConfigForClient returns a tls.Config based on the given
// tls.ClientHelloInfo. It will only be called if the Limiter.GetConfigForClient
// sat in tls.Config and client tls handshakes rate limit does not exceeded.
//
// If fn is nil or returns nil, then the original tls.Config will be used
func WithGetConfigForClient(fn func(*tls.ClientHelloInfo) (*tls.Config, error)) Option {
	return optionFunc(func(l *Limiter) {
		l.getConfigForClient = fn
	})
}

// WithLimit defines the maximum frequency of TLS handshakes.
// A zero Limit allows no TLS handshakes.
func WithLimit(r time.Duration) Option {
	return optionFunc(func(l *Limiter) {
		l.r = r
	})
}

// WithBursts defines the maximum number of TLS handshakes.
// A zero Burst allows no TLS handshakes.
func WithBursts(b int) Option {
	return optionFunc(func(l *Limiter) {
		l.b = b
	})
}

// WithTLSHostname apply rate limiting per domain
// by using *tls.ClientHelloInfo.ServerName as a key.
func WithTLSHostname() Option {
	return optionFunc(func(l *Limiter) {
		l.keyFn = func(ci *tls.ClientHelloInfo) string {
			return ci.ServerName
		}
	})
}

// WithTLSClientIP apply rate limiting per IP
// by using *tls.ClientHelloInfo.Conn.RemoteAddr() as a key.
func WithTLSClientIP() Option {
	return optionFunc(func(l *Limiter) {
		l.keyFn = func(ci *tls.ClientHelloInfo) string {
			remoteAddr := ci.Conn.RemoteAddr().String()
			remoteAddr, _, err := net.SplitHostPort(remoteAddr)
			if err != nil {
				return remoteAddr
			}
			return remoteAddr
		}
	})
}

// WithCacheMaxSize defines maximum number of cache entries.
func WithCacheMaxSize(size int) Option {
	return optionFunc(func(l *Limiter) {
		l.cache = libcache.LRU.New(size)
	})
}

// NewLimiter returns a new Limiter that allows TLS handshakes up to rate r and permits
// bursts of at most b tokens.
func NewLimiter(opts ...Option) *Limiter {
	lim := new(Limiter)
	for _, opt := range opts {
		opt.apply(lim)
	}

	if lim.cache == nil {
		lim.cache = libcache.LRU.New(0)
	}

	return lim
}

// Limiter controls how frequently TLS handshakes are allowed to happen.
// It implements a "token bucket" of size b, initially full and refilled
// at rate r tokens per duration.
// Informally, in any large enough time interval, the Limiter limits the
// rate to r tokens per duration, with a maximum burst size of b TLS handshakes.
// See https://en.wikipedia.org/wiki/Token_bucket for more about token buckets.
//
// The zero value is a valid Limiter, but it will reject all TLS handshakes.
// Use NewLimiter to create non-zero Limiters.
//
// Limiter has two main methods, GetCertificate, and GetConfigForClient
// suitable to be used in tls.Config
//
// Each of the two methods consumes a single token.
// If no token is available, It returns error to abort TLS handshake.
// If TLS session resumption is used the rate limiting will not be applied.
//
// Limiter by default applies global rate limiting.
// Use WithTLSHostname or WithTLSClientIP to apply rate limiting per ip or domain.
type Limiter struct {
	cache              libcache.Cache
	r                  time.Duration
	b                  int
	keyFn              func(*tls.ClientHelloInfo) string
	getCertificate     func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	getConfigForClient func(*tls.ClientHelloInfo) (*tls.Config, error)
}

func (lim *Limiter) GetCertificate(ci *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if err := lim.limit(ci); err != nil || lim.getCertificate == nil {
		return nil, err
	}

	return lim.getCertificate(ci)
}

func (lim *Limiter) GetConfigForClient(ci *tls.ClientHelloInfo) (*tls.Config, error) {
	if err := lim.limit(ci); err != nil || lim.getConfigForClient == nil {
		return nil, err
	}

	return lim.getConfigForClient(ci)
}

func (lim *Limiter) limit(ci *tls.ClientHelloInfo) error {
	var key = "global"

	if lim.cache == nil {
		return nil
	}

	if lim.keyFn != nil {
		key = lim.keyFn(ci)
	}

	v, ok := lim.cache.Load(key)
	if !ok && lim.r > 0 {
		v = rate.NewLimiter(rate.Every(lim.r), lim.b)
		lim.cache.StoreWithTTL(key, v, lim.r)
	}

	if lim.r <= 0 || !v.(*rate.Limiter).Allow() {
		return errors.New("tlslimit: too many TLS handshakes")
	}

	return nil
}
