// Package dialer provides utilities for creating custom HTTP clients with
// flexible dialing options.
package dialer

import (
	"bepass/config"
	"bepass/logger"
	"bepass/protect"
	"net"
	"runtime"
	"strconv"
)

// TCPDial connects to the destination address.
func TCPDial(network, addr string) (*net.TCPConn, error) {
	var (
		tcpAddr *net.TCPAddr
		err     error
	)
	tcpAddr, err = net.ResolveTCPAddr(network, addr)
	if err != nil {
		return nil, err
	}
	if config.Unix.ProtectSockets && (runtime.GOOS == "android" || runtime.GOOS == "linux") {
		conn, err := protect.NewClientDialer().Dial("tcp", net.JoinHostPort(tcpAddr.IP.String(), strconv.Itoa(tcpAddr.Port)))
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
