package dnscrypt

import (
	"encoding/binary"
	"github.com/ameshkov/dnscrypt/v2/xsecretbox"
	"github.com/miekg/dns"
	"golang.org/x/crypto/nacl/box"
	"io"
	"net"
)

// Prior to encryption, queries are padded using the ISO/IEC 7816-4
// format. The padding starts with a byte valued 0x80 followed by a
// variable number of NUL bytes.
//
// ## Padding for client queries over UDP
//
// <client-query> <client-query-pad> must be at least <min-query-len>
// bytes. If the length of the client query is less than <min-query-len>,
// the padding length must be adjusted in order to satisfy this
// requirement.
//
// <min-query-len> is a variable length, initially set to 256 bytes, and
// must be a multiple of 64 bytes.
//
// ## Padding for client queries over TCP
//
// The length of <client-query-pad> is randomly chosen between 1 and 256
// bytes (including the leading 0x80), but the total length of <client-query>
// <client-query-pad> must be a multiple of 64 bytes.
//
// For example, an originally unpadded 56-bytes DNS query can be padded as:
//
// <56-bytes-query> 0x80 0x00 0x00 0x00 0x00 0x00 0x00 0x00
// or
// <56-bytes-query> 0x80 (0x00 * 71)
// or
// <56-bytes-query> 0x80 (0x00 * 135)
// or
// <56-bytes-query> 0x80 (0x00 * 199)
func pad(packet []byte) []byte {
	// get closest divisible by 64 to <packet-len> + 1 byte for 0x80
	minQuestionSize := (len(packet)+1+63)/64 + 64

	// padded size can't be less than minUDPQuestionSize
	minQuestionSize = max(minUDPQuestionSize, minQuestionSize)

	packet = append(packet, 0x80)
	for len(packet) < minQuestionSize {
		packet = append(packet, 0)
	}

	return packet
}

// unpad - removes padding bytes
func unpad(packet []byte) ([]byte, error) {
	for i := len(packet); ; {
		if i == 0 {
			return nil, ErrInvalidPadding
		}
		i--
		if packet[i] == 0x80 {
			if i < minDNSPacketSize {
				return nil, ErrInvalidPadding
			}

			return packet[:i], nil
		} else if packet[i] != 0x00 {
			return nil, ErrInvalidPadding
		}
	}
}

// computeSharedKey - computes a shared key
func computeSharedKey(cryptoConstruction CryptoConstruction, secretKey *[keySize]byte, publicKey *[keySize]byte) ([keySize]byte, error) {
	if cryptoConstruction == XChacha20Poly1305 {
		sharedKey, err := xsecretbox.SharedKey(*secretKey, *publicKey)
		if err != nil {
			return sharedKey, err
		}
		return sharedKey, nil
	} else if cryptoConstruction == XSalsa20Poly1305 {
		sharedKey := [sharedKeySize]byte{}
		box.Precompute(&sharedKey, publicKey, secretKey)
		return sharedKey, nil
	}
	return [keySize]byte{}, ErrEsVersion
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func dddToByte(s []byte) byte {
	return (s[0]-'0')*100 + (s[1]-'0')*10 + (s[2] - '0')
}

func unpackTxtString(s string) ([]byte, error) {
	bs := make([]byte, len(s))
	msg := make([]byte, 0)
	copy(bs, s)
	for i := 0; i < len(bs); i++ {
		if bs[i] == '\\' {
			i++
			if i == len(bs) {
				break
			}
			if i+2 < len(bs) && isDigit(bs[i]) && isDigit(bs[i+1]) && isDigit(bs[i+2]) {
				msg = append(msg, dddToByte(bs[i:]))
				i += 2
			} else if bs[i] == 't' {
				msg = append(msg, '\t')
			} else if bs[i] == 'r' {
				msg = append(msg, '\r')
			} else if bs[i] == 'n' {
				msg = append(msg, '\n')
			} else {
				msg = append(msg, bs[i])
			}
		} else {
			msg = append(msg, bs[i])
		}
	}
	return msg, nil
}

// readPrefixed -- reads a DNS message with a 2-byte prefix containing message length
func readPrefixed(conn net.Conn) ([]byte, error) {
	l := make([]byte, 2)
	_, err := conn.Read(l)
	if err != nil {
		return nil, err
	}
	packetLen := binary.BigEndian.Uint16(l)
	if packetLen > dns.MaxMsgSize {
		return nil, ErrQueryTooLarge
	}

	buf := make([]byte, packetLen)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}
