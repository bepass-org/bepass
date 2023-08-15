package dialer

import (
	"fmt"
	tls "github.com/refraction-networking/utls"
	"io"
	"math/rand"
	"net"
	"strings"
)

const (
	extensionServerName  uint16 = 0x0
	utlsExtensionPadding uint16 = 0x15
)

func hostnameInSNI(name string) string {
	host := name
	if len(host) > 0 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if i := strings.LastIndex(host, "%"); i > 0 {
		host = host[:i]
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	for len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}

// SNIExtension implements server_name (0)
type SNIExtension struct {
	*tls.GenericExtension
	ServerName string // not an array because go crypto/tls doesn't support multiple SNIs
}

func (e *SNIExtension) Len() int {
	// Literal IP addresses, absolute FQDNs, and empty strings are not permitted as SNI values.
	// See RFC 6066, Section 3.
	hostName := hostnameInSNI(e.ServerName)
	if len(hostName) == 0 {
		return 0
	}
	return 4 + 2 + 1 + 2 + len(hostName)
}

func (e *SNIExtension) Read(b []byte) (int, error) {
	// Literal IP addresses, absolute FQDNs, and empty strings are not permitted as SNI values.
	// See RFC 6066, Section 3.
	hostName := hostnameInSNI(e.ServerName)
	if len(hostName) == 0 {
		return 0, io.EOF
	}
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	// RFC 3546, section 3.1
	b[0] = byte(extensionServerName >> 8)
	b[1] = byte(extensionServerName)
	b[2] = byte((len(hostName) + 5) >> 8)
	b[3] = byte(len(hostName) + 5)
	b[4] = byte((len(hostName) + 3) >> 8)
	b[5] = byte(len(hostName) + 3)
	// b[6] Server Name Type: host_name (0)
	b[7] = byte(len(hostName) >> 8)
	b[8] = byte(len(hostName))
	copy(b[9:], hostName)
	return e.Len(), io.EOF
}

type FakePaddingExtension struct {
	*tls.GenericExtension
	PaddingLen int
	WillPad    bool // set false to disable extension
}

func (e *FakePaddingExtension) Len() int {
	if e.WillPad {
		return 4 + e.PaddingLen
	} else {
		return 0
	}
}

func (e *FakePaddingExtension) Read(b []byte) (n int, err error) {
	if !e.WillPad {
		return 0, io.EOF
	}
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	// https://tools.ietf.org/html/rfc7627
	b[0] = byte(utlsExtensionPadding >> 8)
	b[1] = byte(utlsExtensionPadding)
	b[2] = byte(e.PaddingLen >> 8)
	b[3] = byte(e.PaddingLen)
	x := make([]byte, e.PaddingLen)
	rand.Read(x)
	copy(b[4:], x)
	return e.Len(), io.EOF
}

func (d *Dialer) makeTLSHelloPacketWithPadding(plainConn net.Conn, config *tls.Config, sni string) (*tls.UConn, error) {
	paddingMax := d.TLSPaddingSize[1]
	paddingMin := d.TLSPaddingSize[0]
	paddingSize := paddingMax
	if paddingMax > paddingMin {
		paddingSize = rand.Intn(paddingMax-paddingMin) + paddingMin
	}
	utlsConn := tls.UClient(plainConn, config, tls.HelloCustom)
	spec := tls.ClientHelloSpec{
		TLSVersMax: tls.VersionTLS13,
		TLSVersMin: tls.VersionTLS10,
		CipherSuites: []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_AES_128_GCM_SHA256, // tls 1.3
			tls.FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		Extensions: []tls.TLSExtension{
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{tls.X25519, tls.CurveP256}},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{0}}, // uncompressed
			&tls.SessionTicketExtension{},
			&tls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.PSSWithSHA256,
				tls.PSSWithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA256,
				tls.PKCS1WithSHA384,
				tls.PKCS1WithSHA512,
				tls.ECDSAWithSHA1,
				tls.PKCS1WithSHA1}},
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
				{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: tls.X25519},
			}},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{1}}, // pskModeDHE
			&FakePaddingExtension{
				PaddingLen: paddingSize,
				WillPad:    true,
			},
			&SNIExtension{
				ServerName: sni,
			},
		},
		GetSessionID: nil,
	}
	err := utlsConn.ApplyPreset(&spec)

	if err != nil {
		return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	return utlsConn, nil
}

func (d *Dialer) TLSDial(plainDialer PlainTCPDial, network, addr, hostPort string) (net.Conn, error) {
	sni := strings.Split(addr, ":")[0]
	plainConn, err := plainDialer(network, addr, hostPort)
	if err != nil {
		return nil, err
	}
	config := tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
		MinVersion:         tls.VersionTLS10,
	}

	var utlsConn *tls.UConn

	if d.TLSPaddingEnabled {
		utlsConn, err = d.makeTLSHelloPacketWithPadding(plainConn, &config, sni)
	} else {
		utlsConn = tls.UClient(plainConn, &config, tls.HelloAndroid_11_OkHttp)
	}

	err = utlsConn.Handshake()
	if err != nil {
		_ = plainConn.Close()
		fmt.Println(err)
		return nil, err
	}
	return utlsConn, nil
}