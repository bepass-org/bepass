package server

import (
	"bepass/dialer"
	"bepass/doh"
	"bepass/logger"
	"bepass/resolve"
	"bepass/sni"
	"bepass/socks5"
	"bepass/socks5/statute"
	"bepass/transport"
	"bepass/utils"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ameshkov/dnscrypt/v2"

	"github.com/miekg/dns"
)

// ChunkConfig Constants for chunk lengths and delays.
type ChunkConfig struct {
	TLSHeaderLength int
	BeforeSniLength [2]int
	AfterSniLength  [2]int
	Delay           [2]int
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
	ChunkConfig           ChunkConfig
	WorkerConfig          WorkerConfig
	Dialer                *dialer.Dialer
	BindAddress           string
	EnableLowLevelSockets bool
	LocalResolver         *resolve.LocalResolver
	Transport             *transport.Transport
}

// getHostname This function extracts the tls sni or http
func (s *Server) getHostname(data []byte) ([]byte, []byte, error) {
	hello, err := sni.ReadClientHello(bytes.NewReader(data))
	if err != nil {
		host, data_, err := sni.ParseHTTPHost(bytes.NewReader(data))
		if err != nil {
			return nil, data, err
		}
		return []byte(host), data_, errors.New("http request packet")
	}
	return []byte(hello.ServerName), data, nil
}

func (s *Server) getChunkedPackets(data []byte) (chunks map[int][]byte, host []byte) {
	chunks = make(map[int][]byte)
	host, data_, err := s.getHostname(data)
	if host != nil {
		logger.Infof("Hostname %s", string(host))
	}
	if err != nil {
		chunks[0] = data_
		return
	}
	index := bytes.Index(data, host)
	if index == -1 {
		return nil, nil
	}
	// before sni
	chunks[0] = make([]byte, index)
	copy(chunks[0], data[:index])
	// sni
	chunks[1] = make([]byte, len(host))
	copy(chunks[1], data[index:index+len(host)])
	// after sni
	chunks[2] = make([]byte, len(data)-index-len(host))
	copy(chunks[2], data[index+len(host):])
	return
}

func (s *Server) sendSplitChunks(dst io.Writer, chunks map[int][]byte) {
	chunkLengthMin, chunkLengthMax := s.ChunkConfig.BeforeSniLength[0], s.ChunkConfig.BeforeSniLength[1]
	if len(chunks) > 1 {
		chunkLengthMin, chunkLengthMax = s.ChunkConfig.AfterSniLength[0], s.ChunkConfig.AfterSniLength[1]
	}

	for _, chunk := range chunks {
		position := 0

		for position < len(chunk) {
			var chunkLength int
			if chunkLengthMax-chunkLengthMin > 0 {
				chunkLength = rand.Intn(chunkLengthMax-chunkLengthMin) + chunkLengthMin
			} else {
				chunkLength = chunkLengthMin
			}

			if chunkLength > len(chunk)-position {
				chunkLength = len(chunk) - position
			}

			var delay int
			if s.ChunkConfig.Delay[1]-s.ChunkConfig.Delay[0] > 0 {
				delay = rand.Intn(s.ChunkConfig.Delay[1]-s.ChunkConfig.Delay[0]) + s.ChunkConfig.Delay[0]
			} else {
				delay = s.ChunkConfig.Delay[0]
			}

			_, errWrite := dst.Write(chunk[position : position+chunkLength])
			if errWrite != nil {
				return
			}

			position += chunkLength
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}
}

// Handle handles the SOCKS5 request and forwards traffic to the destination.
func (s *Server) Handle(ctx context.Context, w io.Writer, req *socks5.Request, network string) error {
	fmt.Println("here")
	if s.WorkerConfig.WorkerEnabled &&
		!s.WorkerConfig.WorkerDNSOnly &&
		(network == "udp" || !strings.Contains(s.WorkerConfig.WorkerAddress, req.DstAddr.FQDN) || strings.TrimSpace(req.DstAddr.FQDN) == "") {

		return s.Transport.Handle(network, w, req)
	}

	IPPort, err := s.resolveDestination(ctx, req)
	if err != nil {
		return err
	}

	if err := socks5.SendReply(w, statute.RepSuccess, nil); err != nil {
		logger.Errorf("failed to send reply: %v", err)
		return err
	}

	firstPacket := make([]byte, 32*1024)
	read, err := req.Reader.Read(firstPacket)
	if err != nil {
		return err
	}

	firstPacketChunks, hostname := s.getChunkedPackets(firstPacket[:read])

	// if user has a faulty dns, and it returns dpi ip,
	// we resolve destination based on extracted tls sni or http hostname
	if hostname != nil && strings.Contains(IPPort, "10.10.3") {
		req.RawDestAddr.FQDN = string(hostname)
		IPPort, err = s.resolveDestination(ctx, req)
		if err != nil {
			// if destination resolved to dpi and we cant resolve to actual destination
			// it's pointless to connect to dpi
			return err
		}
	}

	conn, err := s.Dialer.TCPDial("tcp", "", IPPort)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.SetNoDelay(true); err != nil {
		logger.Errorf("failed to set NODELAY option: %v", err)
		return err
	}

	// writing first packet
	s.sendSplitChunks(conn, firstPacketChunks)

	var wg sync.WaitGroup
	wg.Add(2)
	closeSignal := make(chan error, 1)

	go func() {
		_, err := io.Copy(conn, req.Reader)
		if err != nil {
			wg.Done()
		}
	}()

	go func() {
		_, err := io.Copy(w, conn)
		if err != nil {
			wg.Done()
		}
	}()

	go func() {
		wg.Wait()
		close(closeSignal)
	}()

	return <-closeSignal
}

// resolveDestination resolves the destination address using DNS.
func (s *Server) resolveDestination(ctx context.Context, req *socks5.Request) (string, error) {
	dest := req.RawDestAddr

	if dest.FQDN != "" {
		ip, err := s.Resolve(dest.FQDN)
		if err != nil {
			return "", err
		}
		dest.IP = net.ParseIP(ip)
		logger.Infof("resolved %s to %s", req.RawDestAddr, dest)
	} else {
		logger.Infof("skipping resolution for %s", req.RawDestAddr)
	}

	addr := net.JoinHostPort(dest.IP.String(), strconv.Itoa(dest.Port))
	logger.Infof("dialing %s", addr)
	return addr, nil
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
