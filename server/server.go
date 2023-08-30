package server

import (
	"bepass/dialer"
	"bepass/doh"
	"bepass/logger"
	"bepass/resolve"
	"bepass/socks5"
	"bepass/socks5/statute"
	"bepass/transport"
	"bepass/utils"
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"regexp"
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

var sniRegex = regexp.MustCompile(`^(?:[a-z0-9-]+\.)+[a-z]+$`)

// getHostname returns the Server Name Indication (SNI) from a TLS Client Hello message.
func (s *Server) getHostnameRegex(data []byte) ([]byte, error) {
	const (
		sniTypeByte     = 0x00
		sniLengthOffset = 2
	)

	if data[0] != 0x16 {
		return nil, fmt.Errorf("not a tls packet")
	}

	// Find the SNI type byte
	sniTypeIndex := bytes.IndexByte(data, sniTypeByte)
	if sniTypeIndex == -1 {
		return nil, fmt.Errorf("could not find SNI type byte in Server Hello message")
	}

	// Ensure sufficient data to read the SNI length and value
	if len(data) < sniTypeIndex+sniLengthOffset+1 {
		return nil, fmt.Errorf("insufficient data to read SNI length")
	}

	var sni string
	var prev byte
	for i := 0; i < len(data)-1; i++ {
		if prev == 0 && data[i] == 0 {
			start := i + 2
			end := start + int(data[i+1])
			if start < end && end < len(data) {
				str := string(data[start:end])
				if sniRegex.MatchString(str) {
					sni = str
					break
				}
			}
		}
		prev = data[i]
	}
	return []byte(sni), nil
}

// getHostname This function is basically all most folks want to invoke out of this
func (s *Server) getHostname(data []byte) ([]byte, error) {
	extensions, err := s.getExtensionBlock(data)
	shouldUseNewRegexMethod := !s.WorkerConfig.WorkerEnabled || (s.WorkerConfig.WorkerEnabled && s.WorkerConfig.WorkerDNSOnly)
	if err != nil {
		if shouldUseNewRegexMethod {
			return s.getHostnameRegex(data)
		}
		return nil, err
	}
	sn, err := s.getSNBlock(extensions)
	if err != nil {
		if shouldUseNewRegexMethod {
			return s.getHostnameRegex(data)
		}
		return nil, err
	}
	sni, err := s.getSNIBlock(sn)
	if err != nil {
		return s.getHostnameRegex(data)
	}
	return sni, nil
}

/* Return the length computed from the two octets starting at index */
func (s *Server) lengthFromData(data []byte, index int) int {
	if index < 0 || index+1 >= len(data) {
		return 0
	}

	b1 := int(data[index])
	b2 := int(data[index+1])

	return (b1 << 8) + b2
}

// getSNIBlock /* Given a Server Name TLS Extension block, parse out and return the SNI
func (s *Server) getSNIBlock(data []byte) ([]byte, error) {
	index := 0

	for {
		if index >= len(data) {
			break
		}
		length := s.lengthFromData(data, index)
		endIndex := index + 2 + length
		if data[index+2] == 0x00 { /* SNI */
			sni := data[index+3:]
			sniLength := s.lengthFromData(sni, 0)
			return sni[2 : sniLength+2], nil
		}
		index = endIndex
	}
	return []byte{}, fmt.Errorf(
		"finished parsing the SN block without finding an SNI",
	)
}

// getSNBlock finds the SN block given a TLS Extensions data block.
func (s *Server) getSNBlock(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("not enough bytes to be an SN block")
	}

	extensionLength := s.lengthFromData(data, 0)
	if extensionLength+4 > len(data) {
		return nil, fmt.Errorf("extension size is invalid")
	}
	data = data[2 : extensionLength+2]

	for index := 0; index+4 < len(data); {
		blockLength := s.lengthFromData(data, index+2)
		endIndex := index + 4 + blockLength
		if data[index] == 0x00 && data[index+1] == 0x00 {
			return data[index+4 : endIndex], nil
		}

		index = endIndex
	}

	return nil, fmt.Errorf("SN block not found within the Extension block")
}

// getExtensionBlock finds the extension block given a raw TLS Client Hello.
func (s *Server) getExtensionBlock(data []byte) ([]byte, error) {
	dataLen := len(data)
	index := s.ChunkConfig.TLSHeaderLength + 38

	if dataLen <= index+1 {
		return nil, fmt.Errorf("not enough bits to be a Client Hello")
	}

	_, newIndex, err := s.getSessionIDLength(data, index)
	if err != nil {
		return nil, err
	}
	index = newIndex

	_, newIndex, err = s.getCipherListLength(data, index)
	if err != nil {
		return nil, err
	}
	index = newIndex

	_, newIndex, err = s.getCompressionLength(data, index)
	if err != nil {
		return nil, err
	}
	index = newIndex

	if len(data[index:]) == 0 {
		return nil, fmt.Errorf("no extensions")
	}

	return data[index:], nil
}

// getSessionIDLength retrieves the session ID length from the TLS Client Hello data.
func (s *Server) getSessionIDLength(data []byte, index int) (int, int, error) {
	dataLen := len(data)

	if index+1 >= dataLen {
		return 0, 0, fmt.Errorf("not enough bytes for the SessionID")
	}

	sessionIDLength := int(data[index])
	newIndex := index + 1 + sessionIDLength

	if newIndex+2 >= dataLen {
		return 0, 0, fmt.Errorf("not enough bytes for the SessionID")
	}

	return sessionIDLength, newIndex, nil
}

// getCipherListLength retrieves the cipher list length from the TLS Client Hello data.
func (s *Server) getCipherListLength(data []byte, index int) (int, int, error) {
	dataLen := len(data)

	if index+2 >= dataLen {
		return 0, 0, fmt.Errorf("not enough bytes for the Cipher List")
	}

	cipherListLength := s.lengthFromData(data, index)
	newIndex := index + 2 + cipherListLength

	if newIndex+1 >= dataLen {
		return 0, 0, fmt.Errorf("not enough bytes for the Cipher List")
	}

	return cipherListLength, newIndex, nil
}

// getCompressionLength retrieves the compression length from the TLS Client Hello data.
func (s *Server) getCompressionLength(data []byte, index int) (int, int, error) {
	dataLen := len(data)

	if index+1 >= dataLen {
		return 0, 0, fmt.Errorf("not enough bytes for the compression length")
	}

	compressionLength := int(data[index])
	newIndex := index + 1 + compressionLength

	if newIndex >= dataLen {
		return 0, 0, fmt.Errorf("not enough bytes for the compression length")
	}

	return compressionLength, newIndex, nil
}

func (s *Server) getChunkedPackets(data []byte) map[int][]byte {
	chunks := make(map[int][]byte)
	hostname, err := s.getHostname(data)
	if err != nil {
		chunks[0] = data
		return chunks
	}
	logger.Infof("Hostname %s", string(hostname))
	index := bytes.Index(data, hostname)
	if index == -1 {
		return nil
	}
	// before sni
	chunks[0] = make([]byte, index)
	copy(chunks[0], data[:index])
	// sni
	chunks[1] = make([]byte, len(hostname))
	copy(chunks[1], data[index:index+len(hostname)])
	// after sni
	chunks[2] = make([]byte, len(data)-index-len(hostname))
	copy(chunks[2], data[index+len(hostname):])
	return chunks
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

			delay := rand.Intn(s.ChunkConfig.Delay[1]-s.ChunkConfig.Delay[0]) + s.ChunkConfig.Delay[0]

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

	conn, err := s.Dialer.TCPDial("tcp", "", IPPort)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.SetNoDelay(true); err != nil {
		logger.Errorf("failed to set NODELAY option: %v", err)
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

// sendChunks sends chunks from bepass to dst
func (s *Server) sendChunks(dst io.Writer, src io.Reader, shouldSplit bool, wg *sync.WaitGroup) {
	defer wg.Done()
	dataBuffer := make([]byte, 32*1024)

	for index := 0; ; index++ {
		bytesRead, err := src.Read(dataBuffer)
		if bytesRead > 0 {
			// check if it's the first packet and its tls packet
			if index == 0 && dataBuffer[0] == 0x16 && shouldSplit {
				chunks := s.getChunkedPackets(dataBuffer[:bytesRead])
				s.sendSplitChunks(dst, chunks)
			} else {
				_, _ = dst.Write(dataBuffer[:bytesRead])
			}
		}

		if err != nil {
			return
		}
	}
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
	logger.Infof("resolved %s to %s", fqdn, answer.String())
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
