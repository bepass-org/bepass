package dialer

import (
	"bepass/logger"
	"net"
)

type PlainTCPDial func(network, addr, hostPort string) (net.Conn, error)

type Dialer struct {
	Logger                *logger.Std
	EnableLowLevelSockets bool
	TLSPaddingEnabled     bool
	TLSPaddingSize        [2]int
	ProxyAddress          string
}
