package server

import (
	"bytes"
	"context"
	"fmt"
	"github.com/bepass-org/bepass/dialer"
	"github.com/bepass-org/bepass/doh"
	"github.com/bepass-org/bepass/logger"
	"github.com/bepass-org/bepass/resolve"
	"github.com/bepass-org/bepass/sni"
	"github.com/bepass-org/bepass/socks5"
	"github.com/bepass-org/bepass/socks5/statute"
	"github.com/bepass-org/bepass/transport"
	"github.com/bepass-org/bepass/utils"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ameshkov/dnscrypt/v2"

	"github.com/miekg/dns"
)

// FragmentConfig Constants for chunk lengths and delays.
type FragmentConfig struct {
	BSL   [2]int
	ASL   [2]int
	Delay [2]int
}

// WorkerConfig Constants for cloudflare worker.
type WorkerConfig struct {
	WorkerAddress       string
	WorkerIPPortAddress string
	WorkerEnabled       bool
	WorkerDNSOnly       bool
}

type Server struct {
	RemoteDNSAddr         string
	Cache                 *utils.Cache
	ResolveSystem         string
	DoHClient             *doh.Client
	ChunkConfig           FragmentConfig
	WorkerConfig          WorkerConfig
	Dialer                *dialer.Dialer
	BindAddress           string
	EnableLowLevelSockets bool
	LocalResolver         *resolve.LocalResolver
	Transport             *transport.Transport
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
		conn, err = s.Dialer.HttpDial("tcp", IPPort)
	} else {
		conn, err = s.Dialer.FragmentDial("tcp", IPPort)
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
		ip, err := s.Resolve(dest.FQDN)
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

// Resolve resolves the FQDN to an IP address using the specified resolution mechanism.
func (s *Server) Resolve(fqdn string) (string, error) {
	if s.WorkerConfig.WorkerEnabled &&
		strings.Contains(s.WorkerConfig.WorkerAddress, fqdn) {
		dh, _, err := net.SplitHostPort(s.WorkerConfig.WorkerIPPortAddress)
		if strings.Contains(dh, ":") {
			// its ipv6
			dh = "[" + dh + "]"
		}
		if err != nil {
			return "", err
		}
		return dh, nil
	}

	if h := s.LocalResolver.CheckHosts(fqdn); h != "" {
		return h, nil
	}

	if s.ResolveSystem == "doh" {
		u, err := url.Parse(s.RemoteDNSAddr)
		if err == nil {
			if u.Hostname() == fqdn {
				return s.LocalResolver.Resolve(u.Hostname()), nil
			}
		}
	}

	// Ensure fqdn ends with a period
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}

	// Check the cache for fqdn
	if cachedValue, _ := s.Cache.Get(fqdn); cachedValue != nil {
		logger.Infof("using cached value for %s", fqdn)
		return cachedValue.(string), nil
	}

	// Build request message
	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{{
		Name:   fqdn,
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}}

	// Determine which DNS resolution mechanism to use
	var exchange *dns.Msg
	var err error
	switch s.ResolveSystem {
	case "doh":
		exchange, err = s.resolveDNSWithDOH(&req)
	default:
		exchange, err = s.resolveDNSWithDNSCrypt(&req)
	}
	if err != nil {
		return "", err
	}
	// Parse answer and store in cache
	answer := exchange.Answer[0]
	logger.Infof("resolved %s to %s", fqdn, strings.Replace(answer.String(), "\t", " ", -1))
	record := strings.Fields(answer.String())
	if record[3] == "CNAME" {
		ip, err := s.Resolve(record[4])
		if err != nil {
			return "", err
		}
		s.Cache.Set(fqdn, ip)
		return ip, nil
	}
	ip := record[4]
	s.Cache.Set(fqdn, ip)
	return ip, nil
}

// resolveDNSWithDOH resolves DNS using DNS-over-HTTP (DoH) client.
func (s *Server) resolveDNSWithDOH(req *dns.Msg) (*dns.Msg, error) {
	dnsAddr := s.RemoteDNSAddr
	if s.WorkerConfig.WorkerEnabled && s.WorkerConfig.WorkerDNSOnly {
		dnsAddr = s.WorkerConfig.WorkerAddress
	}

	exchange, _, err := s.DoHClient.Exchange(req, dnsAddr)
	if err != nil {
		return nil, err
	}
	if len(exchange.Answer) == 0 {
		return nil, fmt.Errorf("no answer")
	}
	return exchange, nil
}

// resolveDNSWithDNSCrypt resolves DNS using DNSCrypt client.
func (s *Server) resolveDNSWithDNSCrypt(req *dns.Msg) (*dns.Msg, error) {
	c := dnscrypt.Client{
		Net: "tcp", Timeout: 10 * time.Second,
	}
	resolverInfo, err := c.Dial(s.RemoteDNSAddr)
	if err != nil {
		return nil, err
	}
	exchange, err := c.Exchange(req, resolverInfo)
	if err != nil {
		return nil, err
	}
	if len(exchange.Answer) == 0 {
		return nil, fmt.Errorf("no answer")
	}
	return exchange, nil
}
