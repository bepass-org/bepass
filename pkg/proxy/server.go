// Package proxy provides a SOCKS5, SOCKS4/a and http proxy server implementation.
package proxy

import (
	"bepass/pkg/bufferpool"
	"bepass/pkg/logger"
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/elazarl/goproxy"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"slices"
)

// GPool is used to implement custom goroutine pool default use goroutine
type GPool interface {
	Submit(f func()) error
}

// A Request represents a request received by a server, including authentication
// details, addresses, and connection information.
type Request struct {
	Socks5Request
	// LocalAddr of the network server listener
	LocalAddr net.Addr
	// RemoteAddr of the network that sent the request
	RemoteAddr net.Addr
	// DestAddr of the actual destination (might be affected by rewrite)
	DestAddr *AddrSpec
	// Reader for the request's data
	Reader io.Reader
	// RawDestAddr of the desired destination
	RawDestAddr *AddrSpec
}

// ParseRequest creates a new Request from the TCP connection
func ParseRequest(bufConn io.Reader) (*Request, error) {
	hd, err := ParseSocks5Request(bufConn)
	if err != nil {
		return nil, err
	}
	return &Request{
		Socks5Request: hd,
		RawDestAddr:   &hd.DstAddr,
		Reader:        bufConn,
	}, nil
}

// handleRequest is used for request processing after authentication
func (sf *Server) handleRequest(write io.Writer, req *Request) error {
	ctx := context.Background()

	// Switch on the command
	switch req.Command {
	case CommandConnect:
		return sf.ConnectHandle(ctx, write, req)
	case CommandBind:
		return sf.BindHandle(ctx, write, req)
	case CommandAssociate:
		return sf.AssociateHandle(ctx, write, req)
	default:
		if err := SendReply(write, RepCommandNotSupported, nil); err != nil {
			return fmt.Errorf("failed to send reply, %v", err)
		}
		return fmt.Errorf("unsupported command[%v]", req.Command)
	}
}

// Server is responsible for accepting internet and handling
// the details of the SOCKS5 protocol
type Server struct {
	// bindIP is used for bind or udp associate
	bindIP net.IP
	// Optional function for dialing out
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// buffer pool
	bufferPool bufferpool.BufPool
	// goroutine pool
	gPool GPool
	// user's handle
	Socks4ConnectHandle func(ctx context.Context, writer io.Writer, request *Request) error
	ConnectHandle       func(ctx context.Context, writer io.Writer, request *Request) error
	BindHandle          func(ctx context.Context, writer io.Writer, request *Request) error
	AssociateHandle     func(ctx context.Context, writer io.Writer, request *Request) error
	done                chan bool
	listen              net.Listener
	httpProxyBindAddr   string
	bindAddress         string
}

// NewServer creates a new Server
func NewServer() *Server {
	return &Server{
		bufferPool: bufferpool.NewPool(32 * 1024),
		dial: func(ctx context.Context, net_, addr string) (net.Conn, error) {
			return net.Dial(net_, addr)
		},
	}
}

// ListenAndServe is used to create a listener and serve on it
func (sf *Server) ListenAndServe(network, addr string) error {
	prx := goproxy.NewProxyHttpServer()
	prx.Verbose = true

	sf.bindAddress = addr

	// Create a custom dialer with DialContext
	dialer, err := proxy.SOCKS5(network, sf.bindAddress, nil, nil)

	if err != nil {
		return err
	}

	// Don't change this line i know this is deprecated but dialContext doesn't work
	prx.Tr.Dial = dialer.Dial

	// Find a random port and listen to it
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return err
	}

	sf.httpProxyBindAddr = listener.Addr().String()

	errorChan := make(chan error)

	go func() {
		err := http.Serve(listener, prx)
		if err != nil {
			errorChan <- err
			return
		}
	}()

	go func() {
		l, err := net.Listen(network, addr)
		sf.listen = l
		if err != nil {
			errorChan <- err
			return
		}
		errorChan <- sf.Serve()
	}()

	return <-errorChan
}

// Serve is used to serve internet from a listener
func (sf *Server) Serve() error {
	for {
		conn, err := sf.listen.Accept()
		if err != nil {
			select {
			case <-sf.done:
				logger.Info("Shutting socks5 server done")
				return nil
			default:
				logger.Errorf("Accept failed: %v", err)
				return err
			}
		}
		sf.goFunc(func() {
			if err := sf.ServeConn(conn); err != nil {
				logger.Errorf("server: %v", err)
			}
		})
	}
}

// Shutdown gracefully stops the SOCKS5 server. It closes the listener and waits
// for all active connections to complete. This function blocks until the server
// is completely shut down.
func (sf *Server) Shutdown() error {
	go func() { sf.done <- true }() // Shutting down the socks5 proxy
	err := sf.listen.Close()
	if err != nil {
		return err
	}
	return nil
}

// ServeConn is used to serve a single connection.
func (sf *Server) ServeConn(conn net.Conn) error {
	defer func() {
		err := conn.Close()
		if err != nil {
			logger.Errorf("failed to close connection, %v", err)
		}
	}()

	bufConn := bufio.NewReader(conn)

	b, err := bufConn.Peek(1)
	if err != nil {
		return err
	}

	switch b[0] {
	case VersionSocks5:
		return sf.handleSocksRequest(conn, bufConn)
	case VersionSocks4:
		return sf.handleSocks4Request(conn, bufConn)
	default:
		return sf.handleHTTPRequest(conn, bufConn)
	}
}

func (sf *Server) handleHTTPRequest(conn net.Conn, bufConn *bufio.Reader) error {
	// redirect http to socks5
	dstConn, err := net.Dial(sf.listen.Addr().Network(), sf.httpProxyBindAddr)
	if err != nil {
		return err
	}
	defer func() {
		_ = dstConn.Close() // No need to handle the error if there's no specific action to take.
	}()

	errChan := make(chan error)
	go func() {
		_, err := io.Copy(dstConn, bufConn)
		if err != nil {
			errChan <- err
		}
	}()
	go func() {
		_, err := io.Copy(conn, dstConn)
		if err != nil {
			errChan <- err
		}
	}()

	return <-errChan
}

func (sf *Server) handleSocksRequest(conn net.Conn, bufConn *bufio.Reader) error {
	mr, err := ParseMethodRequest(bufConn)
	if err != nil {
		return err
	}

	// Only support no auth
	if !slices.Contains(mr.Methods, MethodNoAuth) {
		// No usable method found
		_, _ = conn.Write([]byte{VersionSocks5, MethodNoAcceptable})
		return fmt.Errorf("unsupported auth methods: %v", mr.Methods)
	}

	// say to client that no auth is required
	_, err = conn.Write([]byte{VersionSocks5, MethodNoAuth})

	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	// The client request detail
	request, err := ParseRequest(bufConn)
	if err != nil {
		if errors.Is(err, ErrUnrecognizedAddrType) {
			if err := SendReply(conn, RepAddrTypeNotSupported, nil); err != nil {
				return fmt.Errorf("failed to send reply %w", err)
			}
		}
		return fmt.Errorf("failed to read destination address, %w", err)
	}

	if request.Socks5Request.Command != CommandConnect &&
		request.Socks5Request.Command != CommandBind &&
		request.Socks5Request.Command != CommandAssociate {
		if err := SendReply(conn, RepCommandNotSupported, nil); err != nil {
			return fmt.Errorf("failed to send reply, %v", err)
		}
		return fmt.Errorf("unrecognized command[%d]", request.Socks5Request.Command)
	}

	request.LocalAddr = conn.LocalAddr()
	request.RemoteAddr = conn.RemoteAddr()
	// Process the client request
	return sf.handleRequest(conn, request)
}

func readAsString(r io.Reader) (string, error) {
	var buff bytes.Buffer
	var b [1]byte
	for {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		if b[0] == 0 {
			break
		}
		buff.Write(b[:])
	}
	return buff.String(), nil
}

func (sf *Server) handleSocks4Request(conn net.Conn, bufConn *bufio.Reader) error {
	var cddstportdstip [1 + 1 + 2 + 4]byte
	var dstHost = ""
	if _, err := io.ReadFull(bufConn, cddstportdstip[:]); err != nil {
		return err
	}
	command := cddstportdstip[1]
	dstPort := binary.BigEndian.Uint16(cddstportdstip[2:4])
	var dstIP net.IP = cddstportdstip[4:] // Change dstIp to dstIP
	if command != uint8(1) {
		return fmt.Errorf("command %d is not supported", command)
	}
	// Skip USERID
	if _, err := readAsString(bufConn); err != nil {
		return err
	}
	// SOCKS4a
	if dstIP[0] == 0 && dstIP[1] == 0 && dstIP[2] == 0 && dstIP[3] != 0 { // Change dstIp to dstIP
		var err error
		dstHost, err = readAsString(bufConn)
		if err != nil {
			return err
		}
	}

	atype := ATYPIPv4

	if dstHost != "" {
		atype = ATYPDomain
	}

	if _, err := conn.Write([]byte{0, 90, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}

	request := &Request{
		Socks5Request: Socks5Request{},
		LocalAddr:     conn.LocalAddr(),
		RemoteAddr:    conn.RemoteAddr(),
		DestAddr:      nil,
		Reader:        bufConn,
		RawDestAddr: &AddrSpec{
			FQDN:     dstHost,
			IP:       dstIP,
			Port:     int(dstPort),
			AddrType: atype,
		},
	}

	if sf.Socks4ConnectHandle != nil {
		return sf.Socks4ConnectHandle(context.Background(), io.Writer(conn), request)
	}
	logger.Errorf("socks4/a without user defined handler is unsupported")
	return errors.New("unsupported")
}

// SendReply is used to send a reply message
// rep: reply status see statute's statute file
func SendReply(w io.Writer, rep uint8, bindAddr net.Addr) error {
	rsp := Reply{
		Version:  VersionSocks5,
		Response: rep,
		BndAddr: AddrSpec{
			AddrType: ATYPIPv4,
			IP:       net.IPv4zero,
			Port:     0,
		},
	}

	if bindAddr != nil {
		if rsp.Response == RepSuccess {
			if tcpAddr, ok := bindAddr.(*net.TCPAddr); ok && tcpAddr != nil {
				rsp.BndAddr.IP = tcpAddr.IP
				rsp.BndAddr.Port = tcpAddr.Port
			} else if udpAddr, ok := bindAddr.(*net.UDPAddr); ok && udpAddr != nil {
				rsp.BndAddr.IP = udpAddr.IP
				rsp.BndAddr.Port = udpAddr.Port
			} else {
				rsp.Response = RepAddrTypeNotSupported
			}

			if rsp.BndAddr.IP.To4() != nil {
				rsp.BndAddr.AddrType = ATYPIPv4
			} else if rsp.BndAddr.IP.To16() != nil {
				rsp.BndAddr.AddrType = ATYPIPv6
			}
		}
	}
	// Send the message
	_, err := w.Write(rsp.Bytes())
	return err
}

func (sf *Server) goFunc(f func()) {
	if sf.gPool == nil || sf.gPool.Submit(f) != nil {
		go f()
	}
}
