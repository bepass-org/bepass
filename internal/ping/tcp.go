package ping

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"
)

type TcpPingResult struct {
	Time int
	Err  error
	IP   net.IP
}

func (tp *TcpPingResult) Result() int {
	return tp.Time
}

func (tp *TcpPingResult) Error() error {
	return tp.Err
}

func (tp *TcpPingResult) String() string {
	if tp.Err != nil {
		return fmt.Sprintf("%s", tp.Err)
	} else {
		return fmt.Sprintf("%s: time=%d ms", tp.IP.String(), tp.Time)
	}
}

type TcpPing struct {
	host    string
	Port    uint16
	Timeout time.Duration

	ip net.IP
}

func (tp *TcpPing) SetHost(host string) {
	tp.host = host
	tp.ip = net.ParseIP(host)
}

func (tp *TcpPing) Host() string {
	return tp.host
}

func (tp *TcpPing) Ping() IPingResult {
	return tp.PingContext(context.Background())
}

func (tp *TcpPing) PingContext(ctx context.Context) IPingResult {
	ip := cloneIP(tp.ip)
	if ip == nil {
		return &TcpPingResult{0, fmt.Errorf("no IP specified"), nil}
	}
	dialer := &net.Dialer{
		Timeout:   tp.Timeout,
		KeepAlive: -1,
	}
	t0 := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.FormatUint(uint64(tp.Port), 10)))
	if err != nil {
		return &TcpPingResult{0, err, nil}
	}
	defer conn.Close()
	return &TcpPingResult{int(time.Since(t0).Milliseconds()), nil, ip}
}

func NewTcpPing(host string, port uint16, timeout time.Duration) *TcpPing {
	return &TcpPing{
		host:    host,
		Port:    port,
		Timeout: timeout,
		ip:      net.ParseIP(host),
	}
}

var (
	_ IPing       = (*TcpPing)(nil)
	_ IPingResult = (*TcpPingResult)(nil)
)
