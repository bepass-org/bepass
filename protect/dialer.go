package protect

import (
	"github.com/daeuniverse/softwind/netproxy"
	"github.com/daeuniverse/softwind/protocol/direct"
)

var protectPath string

type ClientDialer struct {
	netproxy.Dialer
}

func NewClientDialer() *ClientDialer {
	protectPath = "protect_path"
	return &ClientDialer{
		direct.SymmetricDirect,
	}
}

func (c *ClientDialer) Dial(network string, addr string) (netproxy.Conn, error) {
	magicNetwork := netproxy.MagicNetwork{
		Network: network,
		Mark:    114514,
	}
	return c.Dialer.Dial(magicNetwork.Encode(), addr)
}
