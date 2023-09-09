// Package dialer provides utilities for creating custom HTTP clients with
// flexible dialing options.
package dialer

import (
	"context"
	"net"
	"net/http"
	"net/url"
)

// MakeHTTPClient creates an HTTP client with custom dialing behavior.
func (d *Dialer) MakeHTTPClient(enableProxy bool) *http.Client {
	transport := &http.Transport{
		ForceAttemptHTTP2: false,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.TCPDial(network, addr)
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.TLSDial(func(network, addr string) (net.Conn, error) {
				return d.TCPDial(network, addr)
			}, network, addr)
		},
	}
	if enableProxy {
		proxyURL, _ := url.Parse(d.ProxyAddress)

		// Create dialer
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	return &http.Client{Transport: transport}
}
