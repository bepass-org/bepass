package local

import (
	"bepass/config"
	proxy "bepass/local/proxy"
	"bepass/pkg/bufferpool"
	"bepass/proxy"
	"bepass/transport"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

var s5 *proxy.Server

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
		s5 = proxy.NewServer(
			proxy.WithConnectHandle(func(ctx context.Context, w io.Writer, req *proxy.Request) error {
				return serverHandler.HandleTCPTunnel(ctx, w, req, true)
			}),
			proxy.WithSocks4ConnectHandle(func(ctx context.Context, w io.Writer, req *proxy.Request) error {
				return serverHandler.HandleTCPTunnel(ctx, w, req, false)
			}),
			proxy.WithAssociateHandle(func(ctx context.Context, w io.Writer, req *proxy.Request) error {
				return serverHandler.HandleUDPTunnel(ctx, w, req)
			}),
		)
	} else {
		s5 = proxy.NewServer(
			proxy.WithConnectHandle(func(ctx context.Context, w io.Writer, req *proxy.Request) error {
				return serverHandler.HandleTCPFragment(ctx, w, req, true)
			}),
			proxy.WithSocks4ConnectHandle(func(ctx context.Context, w io.Writer, req *proxy.Request) error {
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
