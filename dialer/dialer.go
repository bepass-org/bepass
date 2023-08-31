package dialer

import (
	"net"
)

type PlainTCPDial func(network, addr, hostPort string) (net.Conn, error)

type Dialer struct {
	EnableLowLevelSockets bool
	TLSPaddingEnabled     bool
	TLSPaddingSize        [2]int
	ProxyAddress          string
}
