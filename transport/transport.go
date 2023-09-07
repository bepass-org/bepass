package transport

import (
	"bepass/bufferpool"
	"bepass/dialer"
	"bepass/logger"
	"bepass/socks5"
	"bepass/socks5/statute"
	"bepass/utils"
	"bepass/wsconnadapter"
	"fmt"
	"io"
	"net"
	"strings"
)

type UdpBind struct {
	Source        *net.UDPAddr
	Destination   string
	TCPTunnel     *wsconnadapter.Adapter
	TunnelStatus  bool
	SocksWriter   io.Writer
	SocksReq      *socks5.Request
	AssociateBind *net.UDPConn
	RecvChan      chan UDPPacket
}

type UDPConf struct {
	ReadTimeout     int
	WriteTimeout    int
	LinkIdleTimeout int
}

type Transport struct {
	WorkerAddress string
	BindAddress   string
	Dialer        *dialer.Dialer
	BufferPool    bufferpool.BufPool
	UDPBind       string
	Tunnel        *WSTunnel
}

type UDPPacket struct {
	Channel uint16
	Data    []byte
}

func (t *Transport) Handle(network string, w io.Writer, req *socks5.Request) error {
	// connect to remote server via ws
	if network == "udp" {
		return t.TunnelUDP(w, req)
	}

	tunnelEndpoint, err := utils.WSEndpointHelper(t.WorkerAddress, req.RawDestAddr.String(), network)
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

	conn := wsconnadapter.New(wsConn)
	defer conn.Close()

	if err != nil {
		return err
	}

	// flush ws stream to write
	conn.Write([]byte{})

	errCh := make(chan error, 2)
	go func() { errCh <- t.Copy(req.Reader, conn) }()
	go func() { errCh <- t.Copy(conn, w) }()
	// Wait
	for i := 0; i < 2; i++ {
		e := <-errCh
		if e != nil {
			// return from this function closes target (and conn).
			return e
		}
	}
	return nil
}

func (t *Transport) Copy(reader io.Reader, writer io.Writer) error {
	buf := make([]byte, 32*1024)

	_, err := io.CopyBuffer(writer, reader, buf[:cap(buf)])
	return err
}

func (t *Transport) TunnelUDP(w io.Writer, req *socks5.Request) error {
	udpAddr, err := net.ResolveUDPAddr("udp", t.UDPBind+":0")
	// connect to remote server via ws
	bindLn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		if err := socks5.SendReply(w, statute.RepServerFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply, %v", err)
		}
		return fmt.Errorf("listen udp failed, %v", err)
	}
	fmt.Println(bindLn.LocalAddr())
	if err := socks5.SendReply(w, statute.RepSuccess, bindLn.LocalAddr()); err != nil {
		logger.Errorf("failed to send reply: %v", err)
		return err
	}

	tunnelEndpoint, err := utils.WSEndpointHelper(t.WorkerAddress, req.RawDestAddr.String(), "udp")
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
	udpBind := &UdpBind{
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
