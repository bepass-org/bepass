// Package socks5 provides a SOCKS5 proxy server implementation with authentication
// support, request handling, and connection management. It can serve as a proxy for
// various network applications that support SOCKS5 proxies.
package socks5

import (
	"bepass/bufferpool"
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"

	"golang.org/x/net/proxy"

	"bepass/logger"
	"bepass/socks5/statute"

	"github.com/elazarl/goproxy"
)

// GPool is used to implement custom goroutine pool default use goroutine
type GPool interface {
	Submit(f func()) error
}

// Server is responsible for accepting internet and handling
// the details of the SOCKS5 protocol
type Server struct {
	// authMethods can be provided to implement authentication
	// By default, "no-auth" mode is enabled.
	// For password-based auth use UserPassAuthenticator.
	authMethods []Authenticator
	// If provided, username/password authentication is enabled,
	// by appending a UserPassAuthenticator to AuthMethods. If not provided,
	// and authMethods is nil, then "no-auth" mode is enabled.
	credentials CredentialStore
	// resolver can be provided to do custom name resolution.
	// Defaults to DNSResolver if not provided.
	resolver NameResolver
	// rules is provided to enable custom logic around permitting
	// various commands. If not provided, NewPermitAll is used.
	rules RuleSet
	// rewriter can be used to transparently rewrite addresses.
	// This is invoked before the RuleSet is invoked.
	// Defaults to NoRewrite.
	rewriter AddressRewriter
	// bindIP is used for bind or udp associate
	bindIP net.IP
	// Optional function for dialing out
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// buffer pool
	bufferPool bufferpool.BufPool
	// goroutine pool
	gPool GPool
	// user's handle
	userConnectHandle   func(ctx context.Context, writer io.Writer, request *Request) error
	userBindHandle      func(ctx context.Context, writer io.Writer, request *Request) error
	userAssociateHandle func(ctx context.Context, writer io.Writer, request *Request) error
	done                chan bool
	listen              net.Listener
	httpProxyBindAddr   string
	bindAddress         string
}

// NewServer creates a new Server
func NewServer(opts ...Option) *Server {
	srv := &Server{
		authMethods: []Authenticator{},
		bufferPool:  bufferpool.NewPool(32 * 1024),
		resolver:    DNSResolver{},
		rules:       NewPermitAll(),
		dial: func(ctx context.Context, net_, addr string) (net.Conn, error) {
			return net.Dial(net_, addr)
		},
	}

	for _, opt := range opts {
		opt(srv)
	}

	// Ensure we have at least one authentication method enabled
	if (len(srv.authMethods) == 0) && srv.credentials != nil {
		srv.authMethods = []Authenticator{&UserPassAuthenticator{srv.credentials}}
	}
	if len(srv.authMethods) == 0 {
		srv.authMethods = []Authenticator{&NoAuthAuthenticator{}}
	}

	return srv
}

// ListenAndServe is used to create a listener and serve on it
func (sf *Server) ListenAndServe(network, addr string) error {
	prx := goproxy.NewProxyHttpServer()
	prx.Verbose = true

	sf.bindAddress = addr

	// Create a custom dialer with DialContext
	dialer, err := proxy.SOCKS5(network, sf.bindAddress, nil, proxy.Direct)
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
	defer conn.Close()

	bufConn := bufio.NewReader(conn)

	b, err := bufConn.Peek(1)
	if err != nil {
		return err
	}

	switch b[0] {
	case statute.VersionSocks5:
		return sf.handleSocksRequest(conn, bufConn)
	case statute.VersionSocks4:
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
	var authContext *AuthContext

	mr, err := statute.ParseMethodRequest(bufConn)
	if err != nil {
		return err
	}

	// Authenticate the connection
	userAddr := ""
	if conn.RemoteAddr() != nil {
		userAddr = conn.RemoteAddr().String()
	}
	authContext, err = sf.authenticate(conn, bufConn, userAddr, mr.Methods)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	// The client request detail
	request, err := ParseRequest(bufConn)
	if err != nil {
		if errors.Is(err, statute.ErrUnrecognizedAddrType) {
			if err := SendReply(conn, statute.RepAddrTypeNotSupported, nil); err != nil {
				return fmt.Errorf("failed to send reply %w", err)
			}
		}
		return fmt.Errorf("failed to read destination address, %w", err)
	}

	if request.Request.Command != statute.CommandConnect &&
		request.Request.Command != statute.CommandBind &&
		request.Request.Command != statute.CommandAssociate {
		if err := SendReply(conn, statute.RepCommandNotSupported, nil); err != nil {
			return fmt.Errorf("failed to send reply, %v", err)
		}
		return fmt.Errorf("unrecognized command[%d]", request.Request.Command)
	}

	request.AuthContext = authContext
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
	var destination = ""
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
	destination = net.JoinHostPort(dstIP.String(), strconv.Itoa(int(dstPort)))
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

	if dstHost != "" {
		destination = net.JoinHostPort(dstHost, strconv.Itoa(int(dstPort)))
	}

	if _, err := conn.Write([]byte{0, 90, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}

	d, err := proxy.SOCKS5("tcp", sf.bindAddress, nil, proxy.Direct)
	if err != nil {
		return err
	}
	dstConn, err := d.Dial("tcp", destination)

	if err != nil {
		return err
	}
	var errCh = make(chan error, 2)
	go func() {
		_, err := io.Copy(dstConn, bufConn)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(conn, dstConn)
		errCh <- err
	}()
	err = <-errCh
	if err != nil {
		return err
	}
	return <-errCh
}

// authenticate is used to handle connection authentication
func (sf *Server) authenticate(conn io.Writer, bufConn io.Reader,
	userAddr string, methods []byte) (*AuthContext, error) {
	// Select a usable method
	for _, auth := range sf.authMethods {
		for _, method := range methods {
			if auth.GetCode() == method {
				return auth.Authenticate(bufConn, conn, userAddr)
			}
		}
	}
	// No usable method found
	conn.Write([]byte{statute.VersionSocks5, statute.MethodNoAcceptable}) //nolint: errcheck
	return nil, statute.ErrNoSupportedAuth
}

func (sf *Server) goFunc(f func()) {
	if sf.gPool == nil || sf.gPool.Submit(f) != nil {
		go f()
	}
}
