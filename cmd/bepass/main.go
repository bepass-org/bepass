package main

import (
	"bepass/doh"
	"bepass/logger"
	"bepass/server"
	"bepass/socks5"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cache *ttlcache.Cache[string, string]
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
	err := viper.ReadInConfig()
	if err != nil {
		return nil, err
	}

	var config Config
	err = viper.Unmarshal(&config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func createCache(ttl int) *ttlcache.Cache[string, string] {
	return ttlcache.New(
		ttlcache.WithTTL[string, string](time.Duration(int64(ttl) * int64(time.Minute))),
	)
}

func main() {
	var configPath string

	rootCmd := &cobra.Command{
		Use:   "bepass",
		Short: "bepass is a socks5 proxy server",
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := loadConfig()
			if err != nil {
				return err
			}

			cache = createCache(config.DnsCacheTTL)
			go cache.Start()

			if strings.HasPrefix(config.RemoteDNSAddr, "https://") {
				config.ResolveSystem = "doh"
				config.DoHClient = doh.NewClient(doh.WithTimeout(10 * time.Second))
			} else {
				config.ResolveSystem = "DNSCrypt"
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
				ResolveSystem: config.ResolveSystem,
				DoHClient:     config.DoHClient,
				Logger:        appLogger,
				ChunkConfig:   chunkConfig,
			}

			s5 := socks5.NewServer(
				socks5.WithConnectHandle(serverHandler.Handle),
			)
			fmt.Println("starting socks server: " + config.BindAddress)
			err = s5.ListenAndServe("tcp", config.BindAddress)
			if err != nil {
				return err
			}

			return nil
		},
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
