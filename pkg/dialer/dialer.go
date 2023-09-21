// Package dialer provides functionality for custom network dialing options.
package dialer

import (
	"github.com/uoosef/bepass/pkg/net/adapters/fragment"
	"github.com/uoosef/bepass/pkg/net/adapters/http"
	"net"
)

// PlainTCPDial is a type representing a function for plain TCP dialing.
type PlainTCPDial func(network, addr string) (net.Conn, error)

func FragmentDial(network, addr string) (net.Conn, error) {
	tcpConn, err := TCPDial(network, addr)
	if err != nil {
		return nil, err
	}
	err = tcpConn.SetNoDelay(true)
	if err != nil {
		return nil, err
	}
	return fragment.New(tcpConn), nil
}

func HttpDial(network, addr string) (net.Conn, error) {
	tcpConn, err := TCPDial(network, addr)
	if err != nil {
		return nil, err
	}
	err = tcpConn.SetNoDelay(true)
	if err != nil {
		return nil, err
	}
	return http.New(tcpConn), nil
}
