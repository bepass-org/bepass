// Package proxy provides functionality for handling SOCKS5, socks4/a and http/connect proxy protocol requests.
package proxy

import (
	"io"
)

// MethodRequest is the negotiation method request packet
// The SOCKS handshake method request is formed as follows:
//
// +-----+----------+---------------+
// | VER | NMETHODS |    METHODS    |
// +-----+----------+---------------+
// |  1  |     1    | X'00' - X'FF' |
// +-----+----------+---------------+
type MethodRequest struct {
	Ver      byte
	NMethods byte
	Methods  []byte // 1-255 bytes
}

// ParseMethodRequest parse method request.
func ParseMethodRequest(r io.Reader) (mr MethodRequest, err error) {
	// Read the version byte
	tmp := []byte{0}
	if _, err = r.Read(tmp); err != nil {
		return
	}
	mr.Ver = tmp[0]

	// Read number method
	if _, err = r.Read(tmp); err != nil {
		return
	}
	mr.NMethods, mr.Methods = tmp[0], make([]byte, tmp[0])
	// read methods
	_, err = io.ReadAtLeast(r, mr.Methods, int(mr.NMethods))
	return
}

// Bytes method request to bytes
func (sf MethodRequest) Bytes() []byte {
	b := make([]byte, 0, 2+sf.NMethods)
	b = append(b, sf.Ver, sf.NMethods)
	b = append(b, sf.Methods...)
	return b
}
