// Package proxy provides functionality for handling SOCKS5, socks4/a and http/connect proxy protocol requests.
package proxy

import (
	"errors"
)

// VersionSocks5 socks5 protocol version
const VersionSocks5 = byte(0x05)

// VersionSocks4 socks4 protocol version
const VersionSocks4 = byte(0x04)

// request command defined
const (
	CommandConnect   = byte(0x01)
	CommandBind      = byte(0x02)
	CommandAssociate = byte(0x03)
)

// method defined
const (
	MethodNoAuth       = byte(0x00)
	MethodNoAcceptable = byte(0xff)
)

// address type defined
const (
	ATYPIPv4   = byte(0x01)
	ATYPDomain = byte(0x03)
	ATYPIPv6   = byte(0x04)
)

// reply status
const (
	RepSuccess uint8 = iota
	RepServerFailure
	RepRuleFailure
	RepNetworkUnreachable
	RepHostUnreachable
	RepConnectionRefused
	RepTTLExpired
	RepCommandNotSupported
	RepAddrTypeNotSupported
	// 0x09 - 0xff unassigned
)

var (
	ErrUnrecognizedAddrType = errors.New("unrecognized address type")
)
