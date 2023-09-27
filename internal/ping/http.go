package ping

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type HttpPingResult struct {
	Time   int
	Proto  string
	Status int
	Length int
	Err    error
	IP     net.IP
}

func (h *HttpPingResult) Result() int {
	return h.Time
}

func (h *HttpPingResult) Error() error {
	return h.Err
}

func (h *HttpPingResult) String() string {
	if h.Err != nil {
		return fmt.Sprintf("%s", h.Err)
	} else {
		return fmt.Sprintf("%s: protocol=%s, status=%d, length=%d, time=%d ms", h.IP.String(), h.Proto, h.Status, h.Length, h.Time)
	}
}

type HttpPing struct {
	Method  string
	URL     string
	Timeout time.Duration

	DisableHttp2       bool
	DisableCompression bool
	Insecure           bool
	Referrer           string
	UserAgent          string
	Http3              bool
	IP                 net.IP
}

func (h *HttpPing) Ping() IPingResult {
	return h.PingContext(context.Background())
}

func (h *HttpPing) PingContext(ctx context.Context) IPingResult {
	u, err := url.Parse(h.URL)
	if err != nil {
		return h.errorResult(err)
	}
	orighost := u.Host
	host := u.Hostname()
	port := u.Port()
	ip := cloneIP(h.IP)
	if ip == nil {
		return h.errorResult(fmt.Errorf("no IP specified"))
	}
	ipstr := ip.String()
	if isIPv6(ip) {
		ipstr = fmt.Sprintf("[%s]", ipstr)
	}
	if port != "" {
		u.Host = fmt.Sprintf("%s:%s", ipstr, port)
	} else {
		u.Host = ipstr
	}
	url2 := u.String()

	var transport http.RoundTripper
	if h.Http3 {
		transport = &http3.RoundTripper{
			DisableCompression: h.DisableCompression,
			QuicConfig: &quic.Config{
				KeepAlivePeriod: 0,
			},
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: h.Insecure,
				ServerName:         host,
			},
		}
	} else {
		trans := http.DefaultTransport.(*http.Transport).Clone()
		trans.DisableKeepAlives = true
		trans.MaxIdleConnsPerHost = -1
		trans.DisableCompression = h.DisableCompression
		trans.ForceAttemptHTTP2 = !h.DisableHttp2
		trans.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: h.Insecure,
			ServerName:         host,
		}
		transport = trans
	}

	req, err := http.NewRequestWithContext(ctx, h.Method, url2, nil)
	if err != nil {
		return h.errorResult(err)
	}
	ua := "httping"
	if h.UserAgent != "" {
		ua = h.UserAgent
	}
	req.Header.Set("User-Agent", ua)
	if h.Referrer != "" {
		req.Header.Set("Referer", h.Referrer)
	}
	req.Host = orighost
	client := &http.Client{}
	client.Transport = transport
	client.Timeout = h.Timeout
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	t0 := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return h.errorResult(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return h.errorResult(err)
	}
	return &HttpPingResult{int(time.Since(t0).Milliseconds()), resp.Proto, resp.StatusCode, len(body), nil, ip}
}

func (h *HttpPing) errorResult(err error) *HttpPingResult {
	r := &HttpPingResult{}
	r.Err = err
	return r
}

func NewHttpPing(method, url string, timeout time.Duration) *HttpPing {
	return &HttpPing{
		Method:  method,
		URL:     url,
		Timeout: timeout,
	}
}

var (
	_ IPing       = (*HttpPing)(nil)
	_ IPingResult = (*HttpPingResult)(nil)
)
