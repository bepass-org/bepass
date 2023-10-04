// Package doh provides a DNS-over-HTTPS (DoH) client implementation.
package doh

import (
	"encoding/base64"
	"errors"
	"github.com/bepass-org/bepass/config"
	"github.com/bepass-org/bepass/dialer"
	"github.com/bepass-org/bepass/resolve"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

// ClientOptions represents options for configuring the DNS-over-HTTPS (DoH) client.
type ClientOptions struct {
	EnableDNSFragment bool                   // Enable DNS fragmentation
	Dialer            *dialer.Dialer         // Custom dialer for HTTP requests
	LocalResolver     *resolve.LocalResolver // Local DNS resolver
}

// ClientOption is a function type used for setting client options.
type ClientOption func(*ClientOptions) error

// WithDialer sets the custom dialer for the DoH client.
func WithDialer(b *dialer.Dialer) ClientOption {
	return func(o *ClientOptions) error {
		o.Dialer = b
		return nil
	}
}

// WithDNSFragmentation enables or disables DNS fragmentation for the DoH client.
func WithDNSFragmentation(f bool) ClientOption {
	return func(o *ClientOptions) error {
		o.EnableDNSFragment = f
		return nil
	}
}

// WithLocalResolver sets the local DNS resolver for the DoH client.
func WithLocalResolver(r *resolve.LocalResolver) ClientOption {
	return func(o *ClientOptions) error {
		o.LocalResolver = r
		return nil
	}
}

// Client represents a DNS-over-HTTPS (DoH) client.
type Client struct {
	opt *ClientOptions
}

// NewClient creates a new DoH client with the provided options.
func NewClient(opts ...ClientOption) *Client {
	o := &ClientOptions{}
	for _, f := range opts {
		f(o)
	}
	return &Client{
		opt: o,
	}
}

// HTTPClient performs an HTTP GET request to the given address using the configured client.
func (c *Client) HTTPClient(address string) ([]byte, error) {
	client := c.opt.Dialer.MakeHTTPClient(config.G.WorkerEnabled)
	resp, err := client.Get(address)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		err = errors.New("DoH query failed: " + string(content))
		return nil, err
	}

	return content, nil
}

// Exchange performs a DNS query using DoH to the specified address.
func (c *Client) Exchange(req *dns.Msg, address string) (r *dns.Msg, rtt time.Duration, err error) {
	var (
		buf, b64 []byte
		begin    = time.Now()
		origID   = req.Id
	)

	// Set DNS ID as zero according to RFC8484 (cache-friendly)
	req.Id = 0
	buf, err = req.Pack()
	if err != nil {
		return
	}
	b64 = make([]byte, base64.RawURLEncoding.EncodedLen(len(buf)))
	base64.RawURLEncoding.Encode(b64, buf)

	if config.G.WorkerEnabled {
		address = "https://8.8.4.4/dns-query"
	}

	content, err := c.HTTPClient(address + "?dns=" + string(b64))
	if err != nil {
		return
	}

	r = new(dns.Msg)
	err = r.Unpack(content)
	r.Id = origID
	rtt = time.Since(begin)
	return
}
