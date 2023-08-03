package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"bepass/cache"
	"bepass/doh"
	"bepass/logger"
	"bepass/server"
	"bepass/socks5"
)

type Config struct {
	TLSHeaderLength       int         `mapstructure:"TLSHeaderLength"`
	DnsCacheTTL           int         `mapstructure:"DnsCacheTTL"`
	RemoteDNSAddr         string      `mapstructure:"RemoteDNSAddr"`
	BindAddress           string      `mapstructure:"BindAddress"`
	ChunksLengthBeforeSni [2]int      `mapstructure:"ChunksLengthBeforeSni"`
	SniChunksLength       [2]int      `mapstructure:"SniChunksLength"`
	ChunksLengthAfterSni  [2]int      `mapstructure:"ChunksLengthAfterSni"`
	DelayBetweenChunks    [2]int      `mapstructure:"DelayBetweenChunks"`
	ResolveSystem         string      `mapstructure:"-"`
	DoHClient             *doh.Client `mapstructure:"-"`
}

func loadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

func runServer(cmd *cobra.Command, args []string) error {
	config, err := loadConfig()
	if err != nil {
		return err
	}

	cache := cache.NewCache(time.Duration(config.DnsCacheTTL) * time.Second)

	var resolveSystem string
	var dohClient *doh.Client

	if strings.HasPrefix(config.RemoteDNSAddr, "https://") {
		resolveSystem = "doh"
		dohClient = doh.NewClient(doh.WithTimeout(10 * time.Second))
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

	serverHandler := &server.Server{
		RemoteDNSAddr: config.RemoteDNSAddr,
		Cache:         cache,
		ResolveSystem: resolveSystem,
		DoHClient:     dohClient,
		Logger:        appLogger,
		ChunkConfig:   chunkConfig,
	}

	s5 := socks5.NewServer(
		socks5.WithConnectHandle(serverHandler.Handle),
	)

	fmt.Println("Starting socks server:", config.BindAddress)
	if err := s5.ListenAndServe("tcp", config.BindAddress); err != nil {
		return err
	}

	return nil
}

func main() {
	var configPath string

	rootCmd := &cobra.Command{
		Use:   "bepass",
		Short: "bepass is a socks5 proxy server",
		RunE:  runServer,
	}

	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "./config.json", "Path to configuration file")
	viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))
	viper.SetEnvPrefix("bepass")
	viper.AutomaticEnv()

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
