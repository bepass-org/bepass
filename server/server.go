package server

import (
	"bepass/cache"
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
	"strings"
	"sync"
	"time"

	"github.com/ameshkov/dnscrypt/v2"
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
	Cache         *cache.Cache
	ResolveSystem string
	DoHClient     *doh.Client
	ChunkConfig   ChunkConfig
	Logger        *logger.Std
}

// getHostname returns the Server Name Indication (SNI) from a TLS Client Hello message.
func (s *Server) getHostname(data []byte) ([]byte, error) {
	const (
		sniTypeByte     = 0x00
		sniLengthOffset = 2
	)

	// Find the SNI type byte
	sniTypeIndex := bytes.IndexByte(data, sniTypeByte)
	if sniTypeIndex == -1 {
		return nil, fmt.Errorf("could not find SNI type byte in Server Hello message")
	}

	// Ensure sufficient data to read the SNI length and value
	if len(data) < sniTypeIndex+sniLengthOffset+1 {
		return nil, fmt.Errorf("insufficient data to read SNI length")
	}

	// Read the SNI length
	sniLength := int(data[sniTypeIndex+sniLengthOffset])

	// Calculate the index of the SNI value
	sniValueIndex := sniTypeIndex + sniLengthOffset + 1

	// Ensure sufficient data to read the SNI value
	if len(data) < sniValueIndex+sniLength {
		return nil, fmt.Errorf("insufficient data to read SNI value")
	}

	// Extract and return the SNI value
	sniValue := data[sniValueIndex : sniValueIndex+sniLength]
	return sniValue, nil
}

// getChunkedPackets splits the data into chunks based on SNI and chunk lengths.
func (s *Server) getChunkedPackets(data []byte) map[int][]byte {
	const (
		chunkIndexHostname  = 0
		chunkIndexSNIValue  = 1
		chunkIndexRemainder = 2
	)

	chunks := make(map[int][]byte)
	hostname, err := s.getHostname(data)
	if err != nil {
		s.Logger.Errorf("get hostname error: %v", err)
		chunks[chunkIndexRemainder] = data
		return chunks
	}

	s.Logger.Printf("Hostname %s", string(hostname))
	index := bytes.Index(data, hostname)
	if index == -1 {
		return nil
	}

	chunks[chunkIndexHostname] = make([]byte, index)
	copy(chunks[chunkIndexHostname], data[:index])
	chunks[chunkIndexSNIValue] = make([]byte, len(hostname))
	copy(chunks[chunkIndexSNIValue], data[index:index+len(hostname)])
	chunks[chunkIndexRemainder] = make([]byte, len(data)-index-len(hostname))
	copy(chunks[chunkIndexRemainder], data[index+len(hostname):])
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

		for position < len(chunk) {
			chunkLength := rand.Intn(chunkLengthMax-chunkLengthMin) + chunkLengthMin
			if chunkLength > len(chunk)-position {
				chunkLength = len(chunk) - position
			}

			delay := rand.Intn(config.Delay[1]-config.Delay[0]) + config.Delay[0]

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
	if cachedValue, _ := s.Cache.Get(fqdn); cachedValue != nil {
		s.Logger.Printf("using cached value for %s", fqdn)
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
	s.Logger.Printf("resolved %s to %s", fqdn, answer.String())
	record := strings.Fields(answer.String())
	if record[3] == "CNAME" {
		return s.Resolve(record[4], dohClient)
	}
	ip := record[4]
	s.Cache.Set(fqdn, ip)
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
