package doh

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/miekg/dns"
)

type ClientOptions struct {
	Timeout           time.Duration // Timeout for one DNS query
	Socks5BindAddress string
}

type ClientOption func(*ClientOptions) error

func WithTimeout(t time.Duration) ClientOption {
	return func(o *ClientOptions) error {
		o.Timeout = t
		return nil
	}
}

func WithSocks5(b string) ClientOption {
	return func(o *ClientOptions) error {
		o.Socks5BindAddress = b
		return nil
	}
}

type Client struct {
	opt *ClientOptions
}

func NewClient(opts ...ClientOption) *Client {
	o := &ClientOptions{Timeout: 5 * time.Second} // Default timeout of 5 seconds
	for _, f := range opts {
		f(o)
	}
	return &Client{
		opt: o,
	}
}

func (c *Client) HTTPClient(address string, needsFragmentation bool) ([]byte, error) {
	transport := &http.Transport{}

	if needsFragmentation {
		// if its worker utl it should go through internal socks 5 server inorder to get chunked
		// SOCKS5 proxy URL with remote DNS
		//fmt.Print(c.opt.Socks5BindAddress)
		proxyUrl, _ := url.Parse(c.opt.Socks5BindAddress)

		// Create dialer
		transport.Proxy = http.ProxyURL(proxyUrl)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   c.opt.Timeout,
	}

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

func (c *Client) Exchange(req *dns.Msg, address string, needsFragmentation bool) (r *dns.Msg, rtt time.Duration, err error) {
	var (
		buf, b64 []byte
		begin    = time.Now()
		origID   = req.Id
	)

	// Set DNS ID as zero according to RFC8484 (cache friendly)
	req.Id = 0
	buf, err = req.Pack()
	if err != nil {
		return
	}
	b64 = make([]byte, base64.RawURLEncoding.EncodedLen(len(buf)))
	base64.RawURLEncoding.Encode(b64, buf)

	content, err := c.HTTPClient(address+"?dns="+string(b64), needsFragmentation)
	if err != nil {
		return
	}

	r = new(dns.Msg)
	err = r.Unpack(content)
	r.Id = origID
	rtt = time.Since(begin)
	return
}
