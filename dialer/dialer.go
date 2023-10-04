// Package dialer provides functionality for custom network dialing options.
package dialer

import (
	"github.com/bepass-org/bepass/net/adapter/fragment"
	"github.com/bepass-org/bepass/net/adapter/http"
	"net"
)

// PlainTCPDial is a type representing a function for plain TCP dialing.
type PlainTCPDial func(network, addr string) (net.Conn, error)

// Dialer is a struct that holds various options for custom dialing.
type Dialer struct {
	EnableLowLevelSockets bool   // Enable low-level socket operations.
	TLSPaddingEnabled     bool   // Enable TLS padding.
	TLSPaddingSize        [2]int // Size of TLS padding.
	ProxyAddress          string // Address of the proxy server.
}

func (d *Dialer) FragmentDial(network, addr string) (net.Conn, error) {
	tcpConn, err := d.TCPDial(network, addr)
	if err != nil {
		return nil, err
	}
	err = tcpConn.SetNoDelay(true)
	if err != nil {
		return nil, err
	}
	return fragment.New(tcpConn), nil
}

func (d *Dialer) HttpDial(network, addr string) (net.Conn, error) {
	tcpConn, err := d.TCPDial(network, addr)
	if err != nil {
		return nil, err
	}
	err = tcpConn.SetNoDelay(true)
	if err != nil {
		return nil, err
	}
	return http.New(tcpConn), nil
}
