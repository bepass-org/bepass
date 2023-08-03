package doh

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

const DoHMediaType = "application/dns-message"

type ClientOptions struct {
	Timeout time.Duration // Timeout for one DNS query
}

type ClientOption func(*ClientOptions) error

func WithTimeout(t time.Duration) ClientOption {
	return func(o *ClientOptions) error {
		o.Timeout = t
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

	client := &http.Client{Timeout: c.opt.Timeout}
	resp, err := client.Get(address + "?dns=" + string(b64))
	if err != nil {
		return
	}
	defer resp.Body.Close()

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	if resp.StatusCode != http.StatusOK {
		err = errors.New("DoH query failed: " + string(content))
		return
	}

	r = new(dns.Msg)
	err = r.Unpack(content)
	r.Id = origID
	rtt = time.Since(begin)
	return
}
