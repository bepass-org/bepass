// Package dialer provides functionality for custom network dialing options.
package dialer

import (
	"net"
)

// PlainTCPDial is a type representing a function for plain TCP dialing.
type PlainTCPDial func(network, addr, hostPort string) (net.Conn, error)

// Dialer is a struct that holds various options for custom dialing.
type Dialer struct {
	EnableLowLevelSockets bool   // Enable low-level socket operations.
	TLSPaddingEnabled     bool   // Enable TLS padding.
	TLSPaddingSize        [2]int // Size of TLS padding.
	ProxyAddress          string // Address of the proxy server.
}
