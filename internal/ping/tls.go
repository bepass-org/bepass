package ping

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"
)

type TlsPingResult struct {
	ConnectionTime int
	HandshakeTime  int
	TLSVersion     uint16
	Err            error
	IP             net.IP
}

func (t *TlsPingResult) Result() int {
	return t.ConnectionTime + t.HandshakeTime
}

func (t *TlsPingResult) Error() error {
	return t.Err
}

func (t *TlsPingResult) String() string {
	if t.Err != nil {
		return fmt.Sprintf("%s", t.Err)
	} else {
		return fmt.Sprintf("%s: protocol=%s, connection=%d ms, handshake=%d ms, time=%d ms", t.IP.String(), tlsVersionToString(t.TLSVersion), t.ConnectionTime, t.HandshakeTime, t.Result())
	}
}

type TlsPing struct {
	Host              string
	Port              uint16
	ConnectionTimeout time.Duration
	HandshakeTimeout  time.Duration

	TlsVersion uint16
	Insecure   bool
	IP         net.IP
}

func (t *TlsPing) Ping() IPingResult {
	return t.PingContext(context.Background())
}

func (t *TlsPing) PingContext(ctx context.Context) IPingResult {
	ip := cloneIP(t.IP)

	if ip == nil {
		return t.errorResult(fmt.Errorf("no IP specified"))
	}

	dialer := &net.Dialer{
		Timeout:   t.ConnectionTimeout,
		KeepAlive: -1,
	}
	t0 := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.FormatUint(uint64(t.Port), 10)))
	if err != nil {
		return t.errorResult(err)
	}
	defer conn.Close()
	t1 := time.Now()
	config := &tls.Config{
		ServerName:         t.Host,
		MinVersion:         t.TlsVersion,
		MaxVersion:         t.TlsVersion,
		InsecureSkipVerify: t.Insecure,
	}
	client := tls.Client(conn, config)
	client.SetDeadline(time.Now().Add(t.HandshakeTimeout))
	err = client.Handshake()
	if err != nil {
		return t.errorResult(err)
	}
	defer client.Close()
	t2 := time.Now()
	return &TlsPingResult{int(t1.Sub(t0).Milliseconds()), int(t2.Sub(t1).Milliseconds()), client.ConnectionState().Version, nil, ip}
}

func NewTlsPing(host string, port uint16, ct, ht time.Duration) *TlsPing {
	return &TlsPing{
		Host:              host,
		Port:              port,
		ConnectionTimeout: ct,
		HandshakeTimeout:  ht,
	}
}

func (t *TlsPing) errorResult(err error) *TlsPingResult {
	r := &TlsPingResult{}
	r.Err = err
	return r
}

var (
	_ IPing       = (*TlsPing)(nil)
	_ IPingResult = (*TlsPingResult)(nil)
)
