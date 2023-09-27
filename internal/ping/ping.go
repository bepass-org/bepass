package ping

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
)

type IPingResult interface {
	Result() int
	Error() error
	fmt.Stringer
}

type IPing interface {
	Ping() IPingResult
	PingContext(context.Context) IPingResult
}

func tlsVersionToString(ver uint16) string {
	switch ver {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}

func isIPv4(ip net.IP) bool {
	return len(ip.To4()) == net.IPv4len
}

func isIPv6(ip net.IP) bool {
	return len(ip) == net.IPv6len && !isIPv4(ip)
}

func cloneIP(ip net.IP) net.IP {
	var ip2 net.IP
	if ip != nil {
		ip2 = make(net.IP, len(ip))
		copy(ip2, ip)
	}
	return ip2
}
