package doh

import (
	"bepass/dialer"
	"bepass/resolve"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/miekg/dns"
)

type ClientOptions struct {
	EnableDNSFragment bool
	Dialer            *dialer.Dialer
	LocalResolver     *resolve.LocalResolver
}

type ClientOption func(*ClientOptions) error

func WithDialer(b *dialer.Dialer) ClientOption {
	return func(o *ClientOptions) error {
		o.Dialer = b
		return nil
	}
}

func WithDNSFragmentation(f bool) ClientOption {
	return func(o *ClientOptions) error {
		o.EnableDNSFragment = f
		return nil
	}
}

func WithLocalResolver(r *resolve.LocalResolver) ClientOption {
	return func(o *ClientOptions) error {
		o.LocalResolver = r
		return nil
	}
}

type Client struct {
	opt *ClientOptions
}

func NewClient(opts ...ClientOption) *Client {
	o := &ClientOptions{}
	for _, f := range opts {
		f(o)
	}
	return &Client{
		opt: o,
	}
}

func (c *Client) HTTPClient(address string) ([]byte, error) {
	var client *http.Client
	if c.opt.EnableDNSFragment {
		client = c.opt.Dialer.MakeHTTPClient("", true)
	} else {
		u, err := url.Parse(address)
		if err != nil {
			return nil, err
		}
		dohIP := c.opt.LocalResolver.Resolve(u.Hostname())
		client = c.opt.Dialer.MakeHTTPClient(dohIP+":443", false)
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

func (c *Client) Exchange(req *dns.Msg, address string) (r *dns.Msg, rtt time.Duration, err error) {
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
