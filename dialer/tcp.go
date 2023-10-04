// Package dialer provides utilities for creating custom HTTP clients with
// flexible dialing options.
package dialer

import (
	"github.com/bepass-org/bepass/logger"
	"github.com/bepass-org/bepass/protect"
	"net"
	"runtime"
	"strconv"
)

// TCPDial connects to the destination address.
func (d *Dialer) TCPDial(network, addr string) (*net.TCPConn, error) {
	var (
		tcpAddr *net.TCPAddr
		err     error
	)
	tcpAddr, err = net.ResolveTCPAddr(network, addr)
	if err != nil {
		return nil, err
	}
	if d.EnableLowLevelSockets && (runtime.GOOS == "android" || runtime.GOOS == "linux") {
		dialer := protect.NewClientDialer()
		conn, err := dialer.Dial("tcp", net.JoinHostPort(tcpAddr.IP.String(), strconv.Itoa(tcpAddr.Port)))
		if err != nil {
			return nil, err
		}
		return conn.(*net.TCPConn), nil
	}
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		logger.Errorf("failed to connect to %v: %v", tcpAddr, err)
		return nil, err
	}
	return conn, nil
}
