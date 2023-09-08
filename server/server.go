package server

import (
	"bepass/bufferpool"
	"bepass/config"
	"bepass/dialer"
	"bepass/doh"
	"bepass/resolve"
	"bepass/socks5"
	"bepass/transport"
	"bepass/utils"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var s5 *socks5.Server

func Run(captureCTRLC bool) error {
	appCache := utils.NewCache(time.Duration(config.G.DnsCacheTTL) * time.Second)

	var resolveSystem string
	var dohClient *doh.Client

	localResolver := &resolve.LocalResolver{
		Hosts: config.G.Hosts,
	}

	appDialer := &dialer.Dialer{
		EnableLowLevelSockets: config.G.EnableLowLevelSockets,
		TLSPaddingEnabled:     config.G.TLSPaddingEnabled,
		TLSPaddingSize:        config.G.TLSPaddingSize,
		ProxyAddress:          fmt.Sprintf("socks5://%s", config.G.BindAddress),
	}

	wsTunnel := &transport.WSTunnel{
		BindAddress:        config.G.BindAddress,
		Dialer:             appDialer,
		ReadTimeout:        config.G.UDPReadTimeout,
		WriteTimeout:       config.G.UDPWriteTimeout,
		LinkIdleTimeout:    config.G.UDPLinkIdleTimeout,
		EstablishedTunnels: make(map[string]*transport.EstablishedTunnel),
		ShortClientID:      utils.ShortID(6),
	}

	tunnelTransport := &transport.Transport{
		WorkerAddress: config.G.WorkerAddress,
		BindAddress:   config.G.BindAddress,
		Dialer:        appDialer,
		BufferPool:    bufferpool.NewPool(32 * 1024),
		UDPBind:       config.G.UDPBindAddress,
		Tunnel:        wsTunnel,
	}

	if strings.HasPrefix(config.G.RemoteDNSAddr, "https://") {
		resolveSystem = "doh"
		dohClient = doh.NewClient(
			doh.WithDNSFragmentation((config.G.WorkerEnabled && config.G.WorkerDNSOnly) || config.G.EnableDNSFragmentation),
			doh.WithDialer(appDialer),
			doh.WithLocalResolver(localResolver),
		)
	} else {
		resolveSystem = "DNSCrypt"
	}

	chunkConfig := FragmentConfig{
		BSL:   config.G.SniChunksLength,
		ASL:   config.G.ChunksLengthAfterSni,
		Delay: config.G.DelayBetweenChunks,
	}

	workerConfig := WorkerConfig{
		WorkerAddress:       config.G.WorkerAddress,
		WorkerIPPortAddress: config.G.WorkerIPPortAddress,
		WorkerEnabled:       config.G.WorkerEnabled,
		WorkerDNSOnly:       config.G.WorkerDNSOnly,
	}

	serverHandler := &Server{
		RemoteDNSAddr:         config.G.RemoteDNSAddr,
		Cache:                 appCache,
		ResolveSystem:         resolveSystem,
		DoHClient:             dohClient,
		ChunkConfig:           chunkConfig,
		WorkerConfig:          workerConfig,
		BindAddress:           config.G.BindAddress,
		EnableLowLevelSockets: config.G.EnableLowLevelSockets,
		Dialer:                appDialer,
		LocalResolver:         localResolver,
		Transport:             tunnelTransport,
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

	if workerConfig.WorkerEnabled && !workerConfig.WorkerDNSOnly {
		s5 = socks5.NewServer(
			socks5.WithConnectHandle(func(ctx context.Context, w io.Writer, req *socks5.Request) error {
				return serverHandler.HandleTCPTunnel(ctx, w, req)
			}),
			socks5.WithAssociateHandle(func(ctx context.Context, w io.Writer, req *socks5.Request) error {
				return serverHandler.HandleTCPTunnel(ctx, w, req)
			}),
		)
	} else {
		s5 = socks5.NewServer(
			socks5.WithConnectHandle(func(ctx context.Context, w io.Writer, req *socks5.Request) error {
				return serverHandler.HandleTCPFragment(ctx, w, req)
			}),
		)
	}

	fmt.Println("Starting socks, http server:", config.G.BindAddress)
	if err := s5.ListenAndServe("tcp", config.G.BindAddress); err != nil {
		return err
	}

	return nil
}

func ShutDown() error {
	return s5.Shutdown()
}
