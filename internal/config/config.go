package config

import (
	"encoding/json"
	"fmt"
	"github.com/uoosef/bepass/internal/logger"
	"math/rand"
	"os"
	"time"
)

type server struct {
	Bind   string `json:"bind"`
	Legacy bool   `json:"legacy"`
	Http   bool   `json:"http"`
}

type tls struct {
	Padding struct {
		Enabled     bool   `json:"enabled"`
		LengthRange [2]int `json:"settings"`
	} `json:"padding"`
	AllowInsecure bool   `json:"allow_insecure"`
	Fingerprint   string `json:"fingerprint"`
}

type fragment struct {
	Enable   bool   `json:"enable"`
	Delay    [2]int `json:"delay"`
	Mode     string `json:"mode"`
	Advanced struct {
		Bsl [2]int `json:"bsl"`
		Sl  [2]int `json:"sl"`
		Asl [2]int `json:"asl"`
	} `json:"advanced"`
}

// Hosts represents a domain-to-IP mapping entry in the local hosts file.
type Hosts struct {
	Domain string `json:"domain"`
	IP     string `json:"ip"`
}

type dns struct {
	Strategy string `json:"strategy"`
	Settings struct {
		UseIPv4            bool
		UseIPv6            bool
		SearchList         []string
		Ndots              int
		Timeout            time.Duration
		InsecureSkipVerify bool
		TLSHostname        string
	} `json:"settings"`
	Prefer   string  `json:"prefer"`
	Type     string  `json:"type"`
	Address  string  `json:"address"`
	Ttl      int     `json:"ttl"`
	Fragment bool    `json:"fragment"`
	Hosts    []Hosts `json:"hosts"`
}

type worker struct {
	Enable     bool   `json:"enable"`
	Sni        string `json:"sni"`
	Connection struct {
		Type    string   `json:"type"`
		UseIPv6 bool     `json:"useIPv6"`
		Ports   []int    `json:"ports"`
		Hosts   []string `json:"hosts"`
		Refresh int64    `json:"refresh"`
		Timeout int64    `json:"timeout"`
	} `json:"connection"`
}

type udp struct {
	Enable  bool   `json:"enable"`
	Bind    string `json:"bind"`
	Timeout int64  `json:"timeout"`
}

type unix struct {
	Protected bool `json:"protected"`
}

type session struct {
	SessionID string
	ClientID  string
}

type config struct {
	Server   *server   `json:"server"`
	Tls      *tls      `json:"tls"`
	Fragment *fragment `json:"fragment"`
	Dns      *dns      `json:"dns"`
	Worker   *worker   `json:"worker"`
	Udp      *udp      `json:"udp"`
	Unix     *unix     `json:"unix"`
}

var (
	Server   = server{}
	Tls      = tls{}
	Fragment = fragment{}
	Dns      = dns{}
	Worker   = worker{}
	Udp      = udp{}
	Unix     = unix{}
	Session  = session{}
)

func FromJSON(jsonStr []byte) {
	c := config{
		Server:   &Server,
		Tls:      &Tls,
		Fragment: &Fragment,
		Dns:      &Dns,
		Worker:   &Worker,
		Udp:      &Udp,
		Unix:     &Unix,
	}
	if err := json.Unmarshal(jsonStr, &c); err != nil {
		logger.Fatalf("failed to unmarshal config: %v", err)
	}
	Session = session{
		SessionID: fmt.Sprintf("%d", rand.Intn(8999)+1000),
		ClientID:  shortID(6),
	}
	validateConfig()
}

func FromFile(path string) {
	// Read json file content from path
	b, err := os.ReadFile(path) // just pass the file name
	if err != nil {
		logger.Fatalf("failed to read config file: %v", err)
	}
	FromJSON(b)
}
