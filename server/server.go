package server

import (
	"bepass/config"
	"bepass/pkg/bufferpool"
	"bepass/socks5"
	"bepass/transport"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

var s5 *socks5.Server

func Run(captureCTRLC bool) error {
	wsTunnel := &transport.WSTunnel{
		EstablishedTunnels: make(map[string]*transport.EstablishedTunnel),
	}

	tunnelTransport := &transport.Transport{
		BufferPool: bufferpool.NewPool(32 * 1024),
		Tunnel:     wsTunnel,
	}

	serverHandler := &Server{
		Transport: tunnelTransport,
	}

	if captureCTRLC {
		c := make(chan os.Signal)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-c
			_ = ShutDown()
			os.Exit(0)
		}()
	}

	if config.Worker.Enable {
		s5 = socks5.NewServer(
			socks5.WithConnectHandle(func(ctx context.Context, w io.Writer, req *socks5.Request) error {
				return serverHandler.HandleTCPTunnel(ctx, w, req, true)
			}),
			socks5.WithSocks4ConnectHandle(func(ctx context.Context, w io.Writer, req *socks5.Request) error {
				return serverHandler.HandleTCPTunnel(ctx, w, req, false)
			}),
			socks5.WithAssociateHandle(func(ctx context.Context, w io.Writer, req *socks5.Request) error {
				return serverHandler.HandleUDPTunnel(ctx, w, req)
			}),
		)
	} else {
		s5 = socks5.NewServer(
			socks5.WithConnectHandle(func(ctx context.Context, w io.Writer, req *socks5.Request) error {
				return serverHandler.HandleTCPFragment(ctx, w, req, true)
			}),
			socks5.WithSocks4ConnectHandle(func(ctx context.Context, w io.Writer, req *socks5.Request) error {
				return serverHandler.HandleTCPFragment(ctx, w, req, false)
			}),
		)
	}

	fmt.Println("Starting socks, http server:", config.Server.Bind)
	if err := s5.ListenAndServe("tcp", config.Server.Bind); err != nil {
		return err
	}

	return nil
}

func ShutDown() error {
	return s5.Shutdown()
}
