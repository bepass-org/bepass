package config

import (
	"bepass/pkg/logger"
	"bepass/pkg/utils"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
)

var (
	availableFragmentModes = []string{
		// weak|strong|aggressive|custom|advanced
		"weak",
		"strong",
		"aggressive",
		"custom",
		"advanced",
	}
	availableTLSFingerPrints = []string{
		// chrome|edge|firefox|safari|ios|android|auto
		"chrome",
		"edge",
		"firefox",
		"safari",
		"ios",
		"android",
		"auto",
	}
	availableDNSStrategies = []string{
		// direct|proxy
		"direct",
		"proxy",
	}
	availableDNSPrefer = []string{
		// ipv4|ipv6|auto
		"ipv4",
		"ipv6",
		"auto",
	}
	availableDNSTypes = []string{
		// udp|tcp|dot|doh|crypt|system
		"udp",
		"tcp",
		"dot",
		"doh",
		"crypt",
		"system",
	}
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
	Strategy string  `json:"strategy"`
	Prefer   string  `json:"prefer"`
	Type     string  `json:"type"`
	Address  string  `json:"address"`
	Ttl      int     `json:"ttl"`
	Timeout  string  `json:"timeout"`
	Fragment bool    `json:"fragment"`
	Hosts    []Hosts `json:"hosts"`
}

type worker struct {
	Enable  bool   `json:"enable"`
	Sni     string `json:"sni"`
	Host    string `json:"host"`
	Scanner bool   `json:"scanner"`
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
		ClientID:  utils.ShortID(6),
	}
}

func FromFile(path string) {
	// Read json file content from path
	b, err := os.ReadFile(path) // just pass the file name
	if err != nil {
		logger.Fatalf("failed to read config file: %v", err)
	}
	FromJSON(b)
}
