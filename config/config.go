package config

import (
	"bepass/resolve"
)

type Config struct {
	TLSHeaderLength        int             `mapstructure:"TLSHeaderLength"`
	TLSPaddingEnabled      bool            `mapstructure:"TLSPaddingEnabled"`
	TLSPaddingSize         [2]int          `mapstructure:"TLSPaddingSize"`
	DnsCacheTTL            int             `mapstructure:"DnsCacheTTL"`
	DnsRequestTimeout      int             `mapstructure:"DnsRequestTimeout"`
	WorkerAddress          string          `mapstructure:"WorkerAddress"`
	WorkerIPPortAddress    string          `mapstructure:"WorkerIPPortAddress"`
	WorkerEnabled          bool            `mapstructure:"WorkerEnabled"`
	WorkerDNSOnly          bool            `mapstructure:"WorkerDNSOnly"`
	EnableLowLevelSockets  bool            `mapstructure:"EnableLowLevelSockets"`
	EnableDNSFragmentation bool            `mapstructure:"EnableDNSFragmentation"`
	RemoteDNSAddr          string          `mapstructure:"RemoteDNSAddr"`
	BindAddress            string          `mapstructure:"BindAddress"`
	UDPBindAddress         string          `mapstructure:"UDPBindAddress"`
	ChunksLengthBeforeSni  [2]int          `mapstructure:"ChunksLengthBeforeSni"`
	SniChunksLength        [2]int          `mapstructure:"SniChunksLength"`
	ChunksLengthAfterSni   [2]int          `mapstructure:"ChunksLengthAfterSni"`
	UDPReadTimeout         int             `mapstructure:"UDPReadTimeout"`
	UDPWriteTimeout        int             `mapstructure:"UDPWriteTimeout"`
	UDPLinkIdleTimeout     int64           `mapstructure:"UDPLinkIdleTimeout"`
	DelayBetweenChunks     [2]int          `mapstructure:"DelayBetweenChunks"`
	Hosts                  []resolve.Hosts `mapstructure:"Hosts"`
	ResolveSystem          string          `mapstructure:"-"`
}

var G *Config

func init() {
	G = &Config{}
}
