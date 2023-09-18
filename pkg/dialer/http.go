// Package dialer provides utilities for creating custom HTTP clients with
// flexible dialing options.
package dialer

import (
	"bepass/config"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// MakeHTTPClient creates an HTTP client with custom dialing behavior.
func MakeHTTPClient(enableProxy bool, timeout time.Duration) *http.Client {
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: false,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return TCPDial(network, addr)
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return TLSDial(func(network, addr string) (net.Conn, error) {
				return TCPDial(network, addr)
			}, network, addr)
		},
	}
	if enableProxy {
		proxyURL, _ := url.Parse(fmt.Sprintf("socks5://%s", config.Server.Bind))

		// Create dialer
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}
