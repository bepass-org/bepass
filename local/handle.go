package local

import (
	"bytes"
	"context"
	"fmt"
	"github.com/uoosef/bepass/internal/bufferpool"
	"github.com/uoosef/bepass/internal/dialer"
	"github.com/uoosef/bepass/internal/logger"
	"github.com/uoosef/bepass/internal/net/resolvers"
	"github.com/uoosef/bepass/internal/proxy"
	"github.com/uoosef/bepass/internal/sni"
	"github.com/uoosef/bepass/internal/transport"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
)

type Server struct {
	Transport *transport.Transport
}

// extractHostnameOrChangeHTTPHostHeader This function extracts the tls sni or http
func (s *Server) extractHostnameOrChangeHTTPHostHeader(data []byte) (
	hostname []byte, firstPacketData []byte, isHTTP bool, err error) {
	hello, err := sni.ReadClientHello(bytes.NewReader(data))
	if err != nil {
		host, httpPacketData, err := sni.ParseHTTPHost(bytes.NewReader(data))
		if err != nil {
			return nil, data, false, err
		}
		return []byte(host), httpPacketData, true, nil
	}
	return []byte(hello.ServerName), data, false, nil
}

func (s *Server) processFirstPacket(ctx context.Context, w io.Writer, req *proxy.Request, successReply bool) (
	*proxy.Request, string, bool, error,
) {
	if successReply {
		if err := proxy.SendReply(w, proxy.RepSuccess, nil); err != nil {
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

	req.Reader = &transport.BufferedReader{
		FirstPacketData: firstPacketData,
		BufReader:       req.Reader,
		FirstTime:       true,
	}

	return req, IPPort, isHTTP, nil
}

func (s *Server) HandleTCPTunnel(ctx context.Context, w io.Writer, req *proxy.Request, successReply bool) error {
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

// HandleAssociate is used to handle a connect command
func (s *Server) HandleAssociate(ctx context.Context, writer io.Writer, req *proxy.Request) error {
	var err error

	dest, err := s.resolveDestination(ctx, req)
	if err == nil {
		req.RawDestAddr = dest
	}

	target, err := net.Dial("udp", req.DestAddr.String())
	if err != nil {
		msg := err.Error()
		resp := proxy.RepHostUnreachable
		if strings.Contains(msg, "refused") {
			resp = proxy.RepConnectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = proxy.RepNetworkUnreachable
		}
		if err := proxy.SendReply(writer, resp, nil); err != nil {
			return fmt.Errorf("failed to send reply, %v", err)
		}
		return fmt.Errorf("connect to %v failed, %v", req.RawDestAddr, err)
	}
	defer target.Close()

	bindLn, err := net.ListenUDP("udp", nil)
	if err != nil {
		if err := proxy.SendReply(writer, proxy.RepServerFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply, %v", err)
		}
		return fmt.Errorf("listen udp failed, %v", err)
	}
	//defer bindLn.Close()

	logger.Info("", "target addr ", target.RemoteAddr(), " listen addr: ", bindLn.LocalAddr())
	// send BND.ADDR and BND.PORT, client used
	if err = proxy.SendReply(writer, proxy.RepSuccess, bindLn.LocalAddr()); err != nil {
		return fmt.Errorf("failed to send reply, %v", err)
	}

	bufferPool := bufferpool.NewPool(32 * 1024)

	go func() {
		// read from client and write to remote server
		conns := sync.Map{}
		bufPool := bufferPool.Get()
		defer func() {
			target.Close()
			bindLn.Close()
			bufferPool.Put(bufPool)
		}()
		for {
			n, srcAddr, err := bindLn.ReadFrom(bufPool[:cap(bufPool)])
			if err != nil {
				if err == io.EOF {
					return
				}
				if strings.Contains(err.Error(), "use of closed network connection") {
					logger.Errorf("read data from bind listen address %s failed, %v", bindLn.LocalAddr(), err)
					return
				}
				continue
			}

			pk, err := proxy.ParseDatagram(bufPool[:n])
			if err != nil {
				continue
			}

			if _, ok := conns.LoadOrStore(srcAddr.String(), struct{}{}); !ok {
				go func() {
					// read from remote server and write to client
					bufPool := bufferPool.Get()
					defer func() {
						target.Close()
						bindLn.Close()
						bufferPool.Put(bufPool)
					}()

					for {
						buf := bufPool[:cap(bufPool)]
						n, err := target.Read(buf)
						if err != nil {
							if err == io.EOF {
								return
							}
							logger.Errorf("read data from remote %s failed, %v", target.RemoteAddr().String(), err)
							return
						}

						pkb, err := proxy.NewDatagram(target.RemoteAddr().String(), buf[:n])
						if err != nil {
							continue
						}
						tmpBufPool := bufferPool.Get()
						proBuf := tmpBufPool
						proBuf = append(proBuf, pkb.Header()...)
						proBuf = append(proBuf, pkb.Data...)
						if _, err := bindLn.WriteTo(proBuf, srcAddr); err != nil {
							bufferPool.Put(tmpBufPool)
							logger.Errorf("write data to client %s failed, %v", bindLn.LocalAddr(), err)
							return
						}
						bufferPool.Put(tmpBufPool)
					}
				}()
			}

			if _, err := target.Write(pk.Data); err != nil {
				logger.Errorf("write data to remote %s failed, %v", target.RemoteAddr().String(), err)
				return
			}
		}
	}()

	buf := bufferPool.Get()
	defer bufferPool.Put(buf)

	for {
		num, err := req.Reader.Read(buf[:cap(buf)])
		logger.Errorf("read data from client %s, %d bytesm, err is %+v", req.RemoteAddr.String(), num, err)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			if strings.Contains(err.Error(), "use of closed network connection") {
				return err
			}
		}
	}
}

func (s *Server) HandleUDPTunnel(_ context.Context, w io.Writer, req *proxy.Request) error {
	return s.Transport.TunnelUDP(w, req)
}

// HandleTCPFragment handles the SOCKS5 request and forwards traffic to the destination.
func (s *Server) HandleTCPFragment(ctx context.Context, w io.Writer, req *proxy.Request, successReply bool) error {
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

func (s *Server) resolveDestination(_ context.Context, req *proxy.Request) (*proxy.AddrSpec, error) {
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
