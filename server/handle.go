package server

import (
	"bepass/pkg/dialer"
	"bepass/pkg/logger"
	"bepass/pkg/net/resolvers"
	sni2 "bepass/pkg/sni"
	"bepass/pkg/utils"
	"bepass/socks5"
	"bepass/socks5/statute"
	"bepass/transport"
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
)

type Server struct {
	Transport *transport.Transport
}

// extractHostnameOrChangeHTTPHostHeader This function extracts the tls sni or http
func (s *Server) extractHostnameOrChangeHTTPHostHeader(data []byte) (
	hostname []byte, firstPacketData []byte, isHTTP bool, err error) {
	hello, err := sni2.ReadClientHello(bytes.NewReader(data))
	if err != nil {
		host, httpPacketData, err := sni2.ParseHTTPHost(bytes.NewReader(data))
		if err != nil {
			return nil, data, false, err
		}
		return []byte(host), httpPacketData, true, nil
	}
	return []byte(hello.ServerName), data, false, nil
}

func (s *Server) processFirstPacket(ctx context.Context, w io.Writer, req *socks5.Request, successReply bool) (
	*socks5.Request, string, bool, error,
) {
	if successReply {
		if err := socks5.SendReply(w, statute.RepSuccess, nil); err != nil {
			logger.Errorf("failed to send reply: %v", err)
			return nil, "", false, err
		}
	}

	firstPacket := make([]byte, 32*1024)
	read, err := req.Reader.Read(firstPacket)
	if err != nil {
		return nil, "", false, err
	}

	hostname, firstPacketData, isHTTP, err := s.extractHostnameOrChangeHTTPHostHeader(firstPacket[:read])

	if hostname != nil {
		logger.Infof("Hostname %s", string(hostname))
	}

	dest, err := s.resolveDestination(ctx, req)
	if err != nil {
		return nil, "", false, err
	}

	IPPort := net.JoinHostPort(dest.IP.String(), strconv.Itoa(dest.Port))

	// if user has a faulty dns, and it returns dpi ip,
	// we resolve destination based on extracted tls sni or http hostname
	if hostname != nil && strings.Contains(IPPort, "10.10.3") {
		logger.Infof("%s is dpi ip extracting destination host from packets...", IPPort)
		req.RawDestAddr.FQDN = string(hostname)
		dest, err = s.resolveDestination(ctx, req)
		if err != nil {
			// if destination resolved to dpi and we cant resolve to actual destination
			// it's pointless to connect to dpi
			logger.Infof("system was unable to extract destination host from packets!")
			return nil, "", false, err
		}
		IPPort = net.JoinHostPort(dest.IP.String(), strconv.Itoa(dest.Port))
	}

	req.Reader = &utils.BufferedReader{
		FirstPacketData: firstPacketData,
		BufReader:       req.Reader,
		FirstTime:       true,
	}

	return req, IPPort, isHTTP, nil
}

func (s *Server) HandleTCPTunnel(ctx context.Context, w io.Writer, req *socks5.Request, successReply bool) error {
	r, _, _, err := s.processFirstPacket(ctx, w, req, successReply)
	if err != nil {
		return err
	}
	dest, err := s.resolveDestination(ctx, req)
	if err == nil {
		req.RawDestAddr = dest
	}
	return s.Transport.TunnelTCP(w, r)
}

func (s *Server) HandleUDPTunnel(_ context.Context, w io.Writer, req *socks5.Request) error {
	return s.Transport.TunnelUDP(w, req)
}

// HandleTCPFragment handles the SOCKS5 request and forwards traffic to the destination.
func (s *Server) HandleTCPFragment(ctx context.Context, w io.Writer, req *socks5.Request, successReply bool) error {
	r, IPPort, isHTTP, err := s.processFirstPacket(ctx, w, req, successReply)
	if err != nil {
		return err
	}

	logger.Infof("Dialing %s...", IPPort)

	var conn net.Conn

	if isHTTP {
		conn, err = dialer.HttpDial("tcp", IPPort)
	} else {
		conn, err = dialer.FragmentDial("tcp", IPPort)
	}

	if err != nil {
		return err
	}
	defer func() {
		_ = conn.Close()
	}()

	// Start proxying
	errCh := make(chan error, 2)
	go func() { errCh <- s.Copy(r.Reader, conn) }()
	go func() { errCh <- s.Copy(conn, w) }()
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

func (s *Server) Copy(reader io.Reader, writer io.Writer) error {
	buf := make([]byte, 32*1024)

	_, err := io.CopyBuffer(writer, reader, buf[:cap(buf)])
	return err
}

func (s *Server) resolveDestination(_ context.Context, req *socks5.Request) (*statute.AddrSpec, error) {
	dest := req.RawDestAddr

	if dest.FQDN != "" {
		ip, err := resolvers.Resolve(dest.FQDN)
		if err != nil {
			return nil, err
		}
		dest.IP = net.ParseIP(ip)
		logger.Infof("resolved %s to %s", req.RawDestAddr, dest)
	} else {
		logger.Infof("skipping resolution for %s", req.RawDestAddr)
	}

	return dest, nil
}
