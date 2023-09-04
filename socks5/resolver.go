// Package socks5 provides functionality for SOCKS5 proxy communication,
// including interfaces and implementations for custom name resolution.
package socks5

import (
	"context"
	"net"
)

// NameResolver is used to implement custom name resolution.
type NameResolver interface {
	Resolve(ctx context.Context, name string) (context.Context, net.IP, error)
}

// DNSResolver uses the system DNS to resolve host names.
type DNSResolver struct{}

// Resolve implements the NameResolver interface to resolve host names using the system DNS.
func (d DNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addr, err := net.ResolveIPAddr("ip", name)
	if err != nil {
		return ctx, nil, err
	}
	return ctx, addr.IP, err
}
