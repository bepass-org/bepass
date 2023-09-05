// Package socks5 provides functionality for configuring options and settings
// for a SOCKS5 proxy server, including options related to authentication,
// custom buffer pools, name resolution, address rewriting, rules for command
// permission, and more.
package socks5

import (
	"bepass/bufferpool"
	"context"
	"io"
	"net"
)

// Option represents user-configurable options for the SOCKS5 server.
type Option func(s *Server)

// WithBufferPool allows users to provide a custom buffer pool for the server.
// By default, a buffer pool with a size of 32k is used.
func WithBufferPool(bufferPool bufferpool.BufPool) Option {
	return func(s *Server) {
		s.bufferPool = bufferPool
	}
}

// WithAuthMethods allows users to specify custom authentication methods for the server.
// By default, "auth-less" mode is enabled. To enable password-based authentication,
// use the UserPassAuthenticator.
func WithAuthMethods(authMethods []Authenticator) Option {
	return func(s *Server) {
		s.authMethods = append(s.authMethods, authMethods...)
	}
}

// WithCredential enables username/password authentication by providing a CredentialStore.
// If not provided, and AuthMethods is nil, "auth-less" mode is enabled.
func WithCredential(cs CredentialStore) Option {
	return func(s *Server) {
		s.credentials = cs
	}
}

// WithResolver allows users to implement custom name resolution for the server.
// Defaults to DNSResolver if not provided.
func WithResolver(res NameResolver) Option {
	return func(s *Server) {
		s.resolver = res
	}
}

// WithRule enables custom logic around permitting various commands. If not provided,
// NewPermitAll is used.
func WithRule(rule RuleSet) Option {
	return func(s *Server) {
		s.rules = rule
	}
}

// WithRewriter can be used to transparently rewrite addresses before invoking the RuleSet.
// Defaults to NoRewrite.
func WithRewriter(rew AddressRewriter) Option {
	return func(s *Server) {
		s.rewriter = rew
	}
}

// WithBindIP is used for bind or UDP associate.
func WithBindIP(ip net.IP) Option {
	return func(s *Server) {
		if len(ip) != 0 {
			s.bindIP = make(net.IP, 0, len(ip))
			s.bindIP = append(s.bindIP, ip...)
		}
	}
}

// WithDial allows users to provide a custom dial function for outgoing connections.
func WithDial(dial func(ctx context.Context, network, addr string) (net.Conn, error)) Option {
	return func(s *Server) {
		s.dial = dial
	}
}

// WithGPool can be used to provide a custom goroutine pool for the server.
func WithGPool(pool GPool) Option {
	return func(s *Server) {
		s.gPool = pool
	}
}

// WithConnectHandle is used to handle a user's connect command.
func WithConnectHandle(h func(ctx context.Context, writer io.Writer, request *Request) error) Option {
	return func(s *Server) {
		s.userConnectHandle = h
	}
}

// WithBindHandle is used to handle a user's bind command.
func WithBindHandle(h func(ctx context.Context, writer io.Writer, request *Request) error) Option {
	return func(s *Server) {
		s.userBindHandle = h
	}
}

// WithAssociateHandle is used to handle a user's associate command.
func WithAssociateHandle(h func(ctx context.Context, writer io.Writer, request *Request) error) Option {
	return func(s *Server) {
		s.userAssociateHandle = h
	}
}
