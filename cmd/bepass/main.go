package main

import (
	"bepass/doh"
	"bepass/server"
	"bepass/socks5"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

var (
	config                Config
	TLSHeaderLength       = 5
	dohClient             *doh.Client
	Cache                 *ttlcache.Cache[string, string]
	resolveSystem         string
	remoteDNSAddr         string
	chunksLengthBeforeSni = [2]int{1, 5}
	sniChunksLength       = [2]int{1, 5}
	chunksLengthAfterSni  = [2]int{1, 5}
	delayBetweenChunks    = [2]int{1, 10}
	bindAddr              = "127.0.0.1:8085"
	dnsCacheTTL           = 30
	flgConfigPath         = flag.String("c", "./config.json", "Path to configuration file")
)

type Config struct {
	TLSHeaderLength       int
	DnsCacheTTL           int
	RemoteDNSAddr         string
	BindAddress           string
	ChunksLengthBeforeSni [2]int
	SniChunksLength       [2]int
	ChunksLengthAfterSni  [2]int
	DelayBetweenChunks    [2]int
}

func main() {
	flag.Parse()

	configData, err := os.ReadFile(*flgConfigPath) // just pass the file name
	if err != nil {
		fmt.Print(err)
	}
	err = json.Unmarshal(configData, &config)
	if err != nil {
		panic(err)
	}
	TLSHeaderLength = config.TLSHeaderLength
	remoteDNSAddr = config.RemoteDNSAddr
	chunksLengthBeforeSni = config.ChunksLengthBeforeSni
	sniChunksLength = config.SniChunksLength
	chunksLengthAfterSni = config.ChunksLengthAfterSni
	delayBetweenChunks = config.DelayBetweenChunks
	bindAddr = config.BindAddress
	dnsCacheTTL = config.DnsCacheTTL

	if strings.Contains(remoteDNSAddr, "https://") {
		resolveSystem = "doh"
		dohClient = doh.NewClient(doh.WithTimeout(10 * time.Second))
	} else {
		resolveSystem = "DNSCrypt"
	}
	cache := ttlcache.New[string, string](
		ttlcache.WithTTL[string, string](time.Duration(int64(dnsCacheTTL) * int64(time.Minute))),
	)
	go cache.Start() // starts automatic expired item deletion
	serverHandler := &server.Server{
		TLSHeaderLength:       TLSHeaderLength,
		DnsCacheTTL:           dnsCacheTTL,
		RemoteDNSAddr:         remoteDNSAddr,
		BindAddress:           bindAddr,
		ChunksLengthBeforeSni: chunksLengthBeforeSni,
		SniChunksLength:       sniChunksLength,
		ChunksLengthAfterSni:  chunksLengthAfterSni,
		DelayBetweenChunks:    delayBetweenChunks,
		Cache:                 cache,
		ResolveSystem:         resolveSystem,
		DoHClient:             dohClient,
	}
	s5 := socks5.NewServer(
		socks5.WithConnectHandle(serverHandler.Handle),
	)
	fmt.Println("starting socks server: " + bindAddr)
	err = s5.ListenAndServe("tcp", bindAddr)
	if err != nil {
		panic("unable to tun socks server")
	}
}
