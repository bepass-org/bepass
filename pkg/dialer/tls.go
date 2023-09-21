// Package dialer provides utilities for creating custom HTTP clients with
// flexible dialing options.
package dialer

import (
	"fmt"
	tls "github.com/refraction-networking/utls"
	"github.com/uoosef/bepass/config"
	"github.com/uoosef/bepass/pkg/logger"
	"io"
	"math/rand"
	"net"
	"slices"
	"strings"
)

const (
	extensionServerName uint16 = 0x0
	tlsExtensionPadding uint16 = 0x15
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

// Len returns the length of the SNIExtension.
func (e *SNIExtension) Len() int {
	// Literal IP addresses, absolute FQDNs, and empty strings are not permitted as SNI values.
	// See RFC 6066, Section 3.
	hostName := hostnameInSNI(e.ServerName)
	if len(hostName) == 0 {
		return 0
	}
	return 4 + 2 + 1 + 2 + len(hostName)
}

// Read reads the SNIExtension.
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

// FakePaddingExtension implements padding (0x15) extension
type FakePaddingExtension struct {
	*tls.GenericExtension
	PaddingLen int
	WillPad    bool // set false to disable extension
}

// Len returns the length of the FakePaddingExtension.
func (e *FakePaddingExtension) Len() int {
	if e.WillPad {
		return 4 + e.PaddingLen
	}
	return 0
}

// Read reads the FakePaddingExtension.
func (e *FakePaddingExtension) Read(b []byte) (n int, err error) {
	if !e.WillPad {
		return 0, io.EOF
	}
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	// https://tools.ietf.org/html/rfc7627
	b[0] = byte(tlsExtensionPadding >> 8)
	b[1] = byte(tlsExtensionPadding)
	b[2] = byte(e.PaddingLen >> 8)
	b[3] = byte(e.PaddingLen)
	x := make([]byte, e.PaddingLen)
	_, err = rand.Read(x)
	if err != nil {
		return 0, err
	}
	copy(b[4:], x)
	return e.Len(), io.EOF
}

// makeTLSHelloPacketWithPadding creates a TLS hello packet with padding.
func makeTLSHelloPacketWithPadding(plainConn net.Conn, cfg *tls.Config, sni string) (*tls.UConn, error) {
	paddingMax := config.Tls.Padding.LengthRange[1]
	paddingMin := config.Tls.Padding.LengthRange[0]
	paddingSize := paddingMin
	if paddingMax-paddingMin > 0 {
		paddingSize = rand.Intn(paddingMax-paddingMin) + paddingMin
	} else if paddingMin < 1 {
		paddingSize = rand.Intn(1) + 1
	} else {
		paddingSize = rand.Intn(paddingMin) + paddingMin
	}

	tlsConn := tls.UClient(plainConn, cfg, tls.HelloCustom)
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
	err := tlsConn.ApplyPreset(&spec)

	if err != nil {
		return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	err = tlsConn.Handshake()

	if err != nil {
		return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	return tlsConn, nil
}

func removeProtocolFromALPN(spec *tls.ClientHelloSpec, protocol string) *tls.ClientHelloSpec {
	alpnExtIndex := slices.IndexFunc(spec.Extensions, func(ext tls.TLSExtension) bool {
		_, ok := ext.(*tls.ALPNExtension)
		return ok
	})
	if alpnExtIndex == -1 {
		return spec
	}

	alpnExt := spec.Extensions[alpnExtIndex].(*tls.ALPNExtension)
	alpnExt.AlpnProtocols = slices.DeleteFunc(alpnExt.AlpnProtocols, func(p string) bool { return p == protocol })

	return spec
}

// TLSDial dials a TLS connection.
func TLSDial(plainDialer PlainTCPDial, network, addr string) (net.Conn, error) {
	sni, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	plainConn, err := plainDialer(network, addr)
	if err != nil {
		return nil, err
	}

	var randomFingerprint tls.ClientHelloID

	modernFingerprints := []tls.ClientHelloID{
		tls.HelloChrome_Auto,
		tls.HelloFirefox_Auto,
		tls.HelloEdge_Auto,
		tls.HelloSafari_Auto,
		tls.HelloIOS_Auto,
		tls.HelloAndroid_11_OkHttp,
	}
	randomFingerprint = modernFingerprints[rand.Intn(len(modernFingerprints))]

	cfg := tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         nil,
		MinVersion:         tls.VersionTLS10,
	}

	var tlsClient *tls.UConn

	if config.Tls.Padding.Enabled {
		tlsConn, handshakeErr := makeTLSHelloPacketWithPadding(plainConn, &cfg, sni)
		if handshakeErr != nil {
			_ = plainConn.Close()
			logger.Errorf("tls padding error %v", handshakeErr)
			return nil, handshakeErr
		}
		return tlsConn, nil
	}

	tlsClient = tls.UClient(plainConn, &cfg, tls.HelloCustom)

	spec, _ := tls.UTLSIdToSpec(randomFingerprint)

	err = tlsClient.ApplyPreset(removeProtocolFromALPN(&spec, "h2"))
	if err != nil {
		return nil, err
	}

	err = tlsClient.Handshake()
	if err != nil {
		_ = plainConn.Close()
		logger.Errorf("tls handshake error %v", err)
		return nil, err
	}
	return tlsClient, nil
}
