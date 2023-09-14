// Package doh provides a DNS-over-HTTPS (DoH) client implementation.
package doh

import (
	"bepass/config"
	"bepass/dialer"
	"bepass/logger"
	"bepass/resolve"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

// Client represents a DNS-over-HTTPS (DoH) client.
type Client struct {
	LocalResolver *resolve.LocalResolver
}

// HTTPClient performs an HTTP GET request to the given address using the configured client.
func (c *Client) HTTPClient(address string) ([]byte, error) {
	client := dialer.MakeHTTPClient(config.Worker.Enable)
	resp, err := client.Get(address)
	if err != nil {
		return nil, err
	}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			logger.Errorf("doh failed to close response body: %v", err)
		}
	}()

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

	if config.Worker.Enable {
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
