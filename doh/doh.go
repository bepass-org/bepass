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

type clientOptions struct {
	Timeout time.Duration // Timeout for one DNS query
}

type ClientOption func(*clientOptions) error

func WithTimeout(t time.Duration) ClientOption {
	return func(o *clientOptions) error {
		o.Timeout = t
		return nil
	}
}

type Client struct {
	opt *clientOptions
}

func NewClient(opts ...ClientOption) *Client {
	o := new(clientOptions)
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

	resp, err := http.Get(address + "?dns=" + string(b64))
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
