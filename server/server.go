package server

import (
	"bepass/doh"
	"bepass/logger"
	"bepass/socks5"
	"bepass/socks5/statute"
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ameshkov/dnscrypt/v2"
	"github.com/jellydator/ttlcache/v3"
	"github.com/miekg/dns"
)

// Constants for chunk lengths and delays.
type ChunkConfig struct {
	BeforeSniLength [2]int
	AfterSniLength  [2]int
	Delay           [2]int
}

type Server struct {
	RemoteDNSAddr string
	Cache         *ttlcache.Cache[string, string]
	ResolveSystem string
	DoHClient     *doh.Client
	ChunkConfig   ChunkConfig
	Logger        *logger.Std
}

// getHostname returns the Server Name Indication (SNI) from a TLS Client Hello message.
func (s *Server) getHostname(data []byte) ([]byte, error) {
	re := regexp.MustCompile(`\x00\x00\x00\x00\x00(?P<Length>.)(?P<SNI>.{0,255})`)
	matches := re.FindSubmatch(data)
	if len(matches) == 0 {
		return nil, fmt.Errorf("could not find SNI in Server Name TLS Extension block")
	}
	return matches[2], nil
}

// getChunkedPackets splits the data into chunks based on SNI and chunk lengths.
func (s *Server) getChunkedPackets(data []byte) map[int][]byte {
	chunks := make(map[int][]byte)
	hostname, err := s.getHostname(data)
	if err != nil {
		s.Logger.Errorf("get hostname error: %v", err)
		chunks[0] = data
		return chunks
	}
	s.Logger.Printf("Hostname %s", string(hostname))
	index := bytes.Index(data, hostname)
	if index == -1 {
		return nil
	}
	chunks[0] = make([]byte, index)
	copy(chunks[0], data[:index])
	chunks[1] = make([]byte, len(hostname))
	copy(chunks[1], data[index:index+len(hostname)])
	chunks[2] = make([]byte, len(data)-index-len(hostname))
	copy(chunks[2], data[index+len(hostname):])
	return chunks
}

// sendSplitChunks sends the chunks to the destination with specified delays.
func (s *Server) sendSplitChunks(dst io.Writer, chunks map[int][]byte, config ChunkConfig) {
	chunkLengthMin, chunkLengthMax := config.BeforeSniLength[0], config.BeforeSniLength[1]
	if len(chunks) > 1 {
		chunkLengthMin, chunkLengthMax = config.AfterSniLength[0], config.AfterSniLength[1]
	}

	for _, chunk := range chunks {
		position := 0
		for {
			chunkLength := rand.Intn(chunkLengthMax-chunkLengthMin) + chunkLengthMin
			delay := rand.Intn(config.Delay[1]-config.Delay[0]) + config.Delay[0]
			endPosition := position + chunkLength
			if endPosition > len(chunk) {
				endPosition = len(chunk)
			}
			_, errWrite := dst.Write(chunk[position:endPosition])
			if errWrite != nil {
				return
			}
			position = endPosition
			if position == len(chunk) {
				break
			}
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}
}

// Handle handles the SOCKS5 request and forwards traffic to the destination.
func (s *Server) Handle(ctx context.Context, w io.Writer, req *socks5.Request) error {
	dest, err := s.resolveDestination(ctx, req)
	if err != nil {
		return err
	}

	if err := socks5.SendReply(w, statute.RepSuccess, nil); err != nil {
		s.Logger.Errorf("failed to send reply: %v", err)
		return err
	}

	conn, err := s.connectToDestination(dest)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.SetNoDelay(true); err != nil {
		s.Logger.Errorf("failed to set NODELAY option: %v", err)
		return err
	}

	var wg sync.WaitGroup
	wg.Add(2)
	closeSignal := make(chan error, 1)

	go s.sendChunks(conn, req.Reader, true, &wg)
	go s.sendChunks(w, conn, false, &wg)

	go func() {
		wg.Wait()
		close(closeSignal)
	}()

	return <-closeSignal
}

// resolveDestination resolves the destination address using DNS.
func (s *Server) resolveDestination(ctx context.Context, req *socks5.Request) (*net.TCPAddr, error) {
	dohClient := s.DoHClient
	dest := req.RawDestAddr

	if dest.FQDN != "" {
		ip, err := s.Resolve(dest.FQDN, dohClient)
		if err != nil {
			return nil, err
		}
		dest.IP = net.ParseIP(ip)
		s.Logger.Printf("resolved %s to %s", req.RawDestAddr, dest)
	} else {
		s.Logger.Printf("skipping resolution for %s", req.RawDestAddr)
	}

	addr := &net.TCPAddr{IP: dest.IP, Port: dest.Port}
	s.Logger.Printf("dialing %s", addr)
	return addr, nil
}

// connectToDestination connects to the destination address.
func (s *Server) connectToDestination(addr *net.TCPAddr) (*net.TCPConn, error) {
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		s.Logger.Errorf("failed to connect to %s: %v", addr, err)
		return nil, err
	}
	return conn, nil
}

// sendChunks sends chunks from src to dst
func (s *Server) sendChunks(dst io.Writer, src io.Reader, shouldSplit bool, wg *sync.WaitGroup) {
	defer wg.Done()
	buffer := make([]byte, 256*1024)

	for index := 0; ; index++ {
		bytesRead, err := src.Read(buffer)
		if bytesRead > 0 {
			if index == 0 && shouldSplit {
				chunks := s.getChunkedPackets(buffer[:bytesRead])
				s.sendSplitChunks(dst, chunks, s.ChunkConfig)
			} else {
				_, _ = dst.Write(buffer[:bytesRead])
			}
		}

		if err != nil {
			return
		}
	}
}

// Resolve resolves the FQDN to an IP address using the specified resolution mechanism.
func (s *Server) Resolve(fqdn string, dohClient *doh.Client) (string, error) {
	// Ensure fqdn ends with a period
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}

	// Check the cache for fqdn
	if cachedValue := s.Cache.Get(fqdn); cachedValue != nil {
		s.Logger.Printf("using cached value for %s", fqdn)
		return cachedValue.Value(), nil
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
	s.Logger.Printf("resolved %s to %s", fqdn, answer.String())
	record := strings.Fields(answer.String())
	if record[3] == "CNAME" {
		return s.Resolve(record[4], dohClient)
	}

	ttl, err := strconv.Atoi(record[1])
	if err != nil {
		return "", fmt.Errorf("invalid TTL value: %v", err)
	}

	ip := record[4]
	s.Cache.Set(fqdn, ip, time.Duration(ttl)*time.Second)
	return ip, nil
}

// resolveDNSWithDOH resolves DNS using DNS-over-HTTP (DoH) client.
func (s *Server) resolveDNSWithDOH(req *dns.Msg) (*dns.Msg, error) {
	dohClient := doh.NewClient()
	exchange, _, err := dohClient.Exchange(req, s.RemoteDNSAddr)
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
	c := dnscrypt.Client{Net: "tcp", Timeout: 10 * time.Second}
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
