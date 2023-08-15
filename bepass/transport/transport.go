package transport

import (
	"bepass/dialer"
	"bepass/logger"
	"bepass/socks5"
	"bepass/socks5/statute"
	"bepass/wsconnadapter"
	"context"
	"fmt"
	"github.com/gorilla/websocket"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/url"
	"strings"
)

func socks5TCPDial(ctx context.Context, network, addr, socks5BindAddress string) (net.Conn, error) {
	d, err := proxy.SOCKS5("tcp", socks5BindAddress, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	return d.Dial(network, addr)
}

func wsDialer(workerAddress, socks5BindAddress string, dialer *dialer.Dialer) (*websocket.Conn, error) {
	d := websocket.Dialer{
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return socks5TCPDial(ctx, network, addr, socks5BindAddress)
		},

		NetDialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.TLSDial(func(network, addr, hostPort string) (net.Conn, error) {
				return socks5TCPDial(ctx, network, addr, socks5BindAddress)
			}, network, addr, "")
		},
	}

	conn, _, err := d.Dial(workerAddress, nil)
	return conn, err
}

func TunnelToWorkerThroughWs(ctx context.Context, w io.Writer, req *socks5.Request, workerAddress, socks5BindAddress string, logger *logger.Std, dialer *dialer.Dialer) error {
	// connect to remote server via ws
	u, err := url.Parse(workerAddress)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("wss://%s/connect?host=%s&port=%s", u.Host, strings.Split(req.DstAddr.String(), ":")[0], strings.Split(req.DstAddr.String(), ":")[1])
	wsConn, err := wsDialer(endpoint, socks5BindAddress, dialer)
	if err != nil {
		if err := socks5.SendReply(w, statute.RepServerFailure, nil); err != nil {
			return err
		}
		logger.Printf("Can not connect: %v\n", err)
		return err
	}

	conn := wsconnadapter.New(wsConn)

	errCh := make(chan error, 2)

	// upload path
	go func() { errCh <- Copy(req.Reader, conn) }()

	// download path
	go func() { errCh <- Copy(conn, w) }()

	// Wait
	err = <-errCh
	if err != nil &&
		(!strings.Contains(err.Error(), "websocket: close 1006") ||
			!strings.Contains(err.Error(), "websocket: close 1005")) {
		fmt.Println("transport error:", err)
	}

	conn.Close()
	return err
}

func Copy(reader io.Reader, writer io.Writer) error {
	buf := make([]byte, 256*1024)

	_, err := io.CopyBuffer(writer, reader, buf[:cap(buf)])
	return err
}
