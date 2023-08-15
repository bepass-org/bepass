package dialer

import (
	"context"
	"net"
	"net/http"
	"net/url"
)

func (d *Dialer) MakeHTTPClient(hostPort string, enableProxy bool) *http.Client {
	transport := &http.Transport{
		ForceAttemptHTTP2: false,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.TCPDial(network, addr, hostPort)
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.TLSDial(func(network, addr, hostPort string) (net.Conn, error) {
				return d.TCPDial(network, addr, hostPort)
			}, network, addr, hostPort)
		},
	}
	if enableProxy {
		proxyUrl, _ := url.Parse(d.ProxyAddress)

		// Create dialer
		transport.Proxy = http.ProxyURL(proxyUrl)
	}
	return &http.Client{Transport: transport}
}
