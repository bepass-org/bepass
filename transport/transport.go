// Package transport provides network transport functionality.
package transport

import (
	"bepass/config"
	"bepass/pkg/bufferpool"
	"bepass/pkg/logger"
	"bepass/pkg/net/adapters/ws"
	"bepass/pkg/utils"
	"bepass/socks5"
	"bepass/socks5/statute"
	"fmt"
	"io"
	"net"
	"strings"
)

// UDPBind represents a UDP binding configuration.
type UDPBind struct {
	Source        *net.UDPAddr
	Destination   string
	TCPTunnel     *ws.Adapter
	TunnelStatus  bool
	SocksWriter   io.Writer
	SocksReq      *socks5.Request
	AssociateBind *net.UDPConn
	RecvChan      chan UDPPacket
}

// Transport represents the transport layer.
type Transport struct {
	BufferPool bufferpool.BufPool
	Tunnel     *WSTunnel
}

// UDPPacket represents a UDP packet.
type UDPPacket struct {
	Channel uint16
	Data    []byte
}

// TunnelTCP handles tcp network traffic.
func (t *Transport) TunnelTCP(w io.Writer, req *socks5.Request) error {
	tunnelEndpoint, err := utils.WSEndpointHelper(config.Worker.Sni, req.RawDestAddr.String(), "tcp", config.Session.SessionID)
	if err != nil {
		if err := socks5.SendReply(w, statute.RepServerFailure, nil); err != nil {
			return err
		}
		logger.Infof("Could not split host and port: %v\n", err)
		return err
	}

	wsConn, err := t.Tunnel.Dial(tunnelEndpoint)
	if err != nil {
		if err := socks5.SendReply(w, statute.RepServerFailure, nil); err != nil {
			return err
		}
		logger.Infof("Can not connect: %v\n", err)
		return err
	}

	conn := ws.New(wsConn)
	defer func() {
		_ = conn.Close()
	}()

	if err != nil {
		return err
	}

	// flush ws stream to write
	_, err = conn.Write([]byte{})
	if err != nil {
		return err
	}

	errCh := make(chan error)
	go func() { errCh <- t.Copy(req.Reader, conn) }()
	go func() { errCh <- t.Copy(conn, w) }()
	// Wait
	e := <-errCh
	if e != nil {
		// return from this function closes target (and conn).
		return e
	}
	return nil
}

// Copy copies data from reader to writer.
func (t *Transport) Copy(reader io.Reader, writer io.Writer) error {
	buf := make([]byte, 32*1024)

	_, err := io.CopyBuffer(writer, reader, buf[:cap(buf)])
	return err
}

// TunnelUDP tunnels UDP packets over WebSocket.
func (t *Transport) TunnelUDP(w io.Writer, req *socks5.Request) error {
	udpAddr, _ := net.ResolveUDPAddr("udp", config.Udp.Bind+":0") // Use _ to indicate the error is intentionally ignored
	// connect to remote server via ws
	bindLn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		if err := socks5.SendReply(w, statute.RepServerFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply, %v", err)
		}
		return fmt.Errorf("listen udp failed, %v", err)
	}
	logger.Infof("listening on %s udp for associate", bindLn.LocalAddr())
	if err := socks5.SendReply(w, statute.RepSuccess, bindLn.LocalAddr()); err != nil {
		logger.Errorf("failed to send reply: %v", err)
		return err
	}

	tunnelEndpoint, err := utils.WSEndpointHelper(config.Worker.Sni, req.RawDestAddr.String(), "udp", config.Session.SessionID)
	if err != nil {
		if err := socks5.SendReply(w, statute.RepServerFailure, nil); err != nil {
			return err
		}
		logger.Infof("Could not split host and port: %v\n", err)
		return err
	}

	bindWriteChannel := make(chan UDPPacket)
	tunnelWriteChannel, channelIndex, err := t.Tunnel.PersistentDial(tunnelEndpoint, bindWriteChannel)
	if err != nil {
		logger.Errorf("Unable to get or create tunnel for udpBindWriteChannel %v\r\n", err)
		return err
	}
	// make new Bind
	udpBind := &UDPBind{
		SocksWriter:   w,
		SocksReq:      req,
		AssociateBind: bindLn,
		Destination:   req.RawDestAddr.String(),
		RecvChan:      bindWriteChannel,
	}
	bufPool := t.BufferPool.Get()
	defer t.BufferPool.Put(bufPool)
	go func() {
		for {
			n, addr, err := udpBind.AssociateBind.ReadFromUDP(bufPool[:cap(bufPool)])
			udpBind.Source = addr
			if err != nil {
				if err == io.EOF {
					break
				}
				if strings.Contains(err.Error(), "use of closed network connection") {
					logger.Errorf("read data from bind listen address %s failed, %v", udpBind.AssociateBind.LocalAddr(), err)
				}
				break
			}
			pk, err := statute.ParseDatagram(bufPool[:n])
			if err != nil {
				continue
			}
			tunnelWriteChannel <- UDPPacket{
				Channel: channelIndex,
				Data:    pk.Data,
			}
		}
	}()
	for {
		datagram := <-udpBind.RecvChan
		pkb, err := statute.NewDatagram(req.RawDestAddr.String(), datagram.Data)
		if err != nil {
			continue
		}
		proBuf := append(pkb.Header(), pkb.Data...)
		_, err = udpBind.AssociateBind.WriteTo(proBuf, udpBind.Source)
		if err != nil {
			return err
		}
	}
}
