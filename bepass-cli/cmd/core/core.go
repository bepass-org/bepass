package core

import (
	"bepass-cli/cache"
	"bepass-cli/doh"
	"bepass-cli/logger"
	"bepass-cli/server"
	"bepass-cli/socks5"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	TLSHeaderLength       int         `mapstructure:"TLSHeaderLength"`
	DnsCacheTTL           int         `mapstructure:"DnsCacheTTL"`
	WorkerAddress         string      `mapstructure:"WorkerAddress"`
	WorkerIPPortAddress   string      `mapstructure:"WorkerIPPortAddress"`
	WorkerEnabled         bool        `mapstructure:"WorkerEnabled"`
	WorkerDNSOnly         bool        `mapstructure:"WorkerDNSOnly"`
	RemoteDNSAddr         string      `mapstructure:"RemoteDNSAddr"`
	BindAddress           string      `mapstructure:"BindAddress"`
	ChunksLengthBeforeSni [2]int      `mapstructure:"ChunksLengthBeforeSni"`
	SniChunksLength       [2]int      `mapstructure:"SniChunksLength"`
	ChunksLengthAfterSni  [2]int      `mapstructure:"ChunksLengthAfterSni"`
	DelayBetweenChunks    [2]int      `mapstructure:"DelayBetweenChunks"`
	ResolveSystem         string      `mapstructure:"-"`
	DoHClient             *doh.Client `mapstructure:"-"`
}

var s5 *socks5.Server

func RunServer(config *Config, captureCTRLC bool) error {
	appCache := cache.NewCache(time.Duration(config.DnsCacheTTL) * time.Second)

	var resolveSystem string
	var dohClient *doh.Client

	if strings.HasPrefix(config.RemoteDNSAddr, "https://") {
		resolveSystem = "doh"
		dohClient = doh.NewClient(
			doh.WithTimeout(10*time.Second),
			doh.WithSocks5(fmt.Sprintf("socks5://%s", config.BindAddress)),
		)
	} else {
		resolveSystem = "DNSCrypt"
	}

	stdLogger := log.New(os.Stderr, "", log.Ldate|log.Ltime)
	appLogger := logger.NewLogger(stdLogger)
	chunkConfig := server.ChunkConfig{
		BeforeSniLength: config.SniChunksLength,
		AfterSniLength:  config.ChunksLengthAfterSni,
		Delay:           config.DelayBetweenChunks,
	}

	workerConfig := server.WorkerConfig{
		WorkerAddress:       config.WorkerAddress,
		WorkerIPPortAddress: config.WorkerIPPortAddress,
		WorkerEnabled:       config.WorkerEnabled,
		WorkerDNSOnly:       config.WorkerDNSOnly,
	}

	serverHandler := &server.Server{
		RemoteDNSAddr: config.RemoteDNSAddr,
		Cache:         appCache,
		ResolveSystem: resolveSystem,
		DoHClient:     dohClient,
		Logger:        appLogger,
		ChunkConfig:   chunkConfig,
		WorkerConfig:  workerConfig,
		BindAddress:   config.BindAddress,
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

	s5 = socks5.NewServer(
		socks5.WithConnectHandle(serverHandler.Handle),
	)

	fmt.Println("Starting socks server:", config.BindAddress)
	if err := s5.ListenAndServe("tcp", config.BindAddress); err != nil {
		return err
	}

	return nil
}

func ShutDown() error {
	return s5.Shutdown()
}
