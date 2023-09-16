// Package protect provides functionality for protecting network connections.
package protect

import (
	"github.com/daeuniverse/softwind/netproxy"
	"github.com/daeuniverse/softwind/protocol/direct"
)

var protectPath string

// ClientDialer provides dialing functionality with protection.
type ClientDialer struct {
	netproxy.Dialer
}

// NewClientDialer creates a new instance of ClientDialer.
func NewClientDialer() *ClientDialer {
	protectPath = "protect_path"
	return &ClientDialer{
		Dialer: direct.SymmetricDirect,
	}
}

// Dial dials the network and address.
func (c *ClientDialer) Dial(network string, addr string) (netproxy.Conn, error) {
	magicNetwork := netproxy.MagicNetwork{
		Network: network,
		Mark:    114514,
	}
	return c.Dialer.Dial(magicNetwork.Encode(), addr)
}
