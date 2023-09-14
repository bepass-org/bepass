package config

import (
	"bepass/logger"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
)

var js = []byte(`
{
  "server": {
    "bind": "0.0.0.0:8085",
    "legacy": true,
    "http": true
  },
  "tls": {
    "padding": {
      "enabled": false,
      "settings": {
        "length": [
          40,
          80
        ]
      }
    },
	"allow_insecure": true,
	"fingerprint": "chrome|edge|firefox|safari|ios|android",
  },
  "fragment": {
    "enable": true,
    "delay": [
      10,
      30
    ],
    "mode": "weak|strong|aggressive|advanced",
    "advanced": {
      "bsl": [
        2000,
        2000
      ],
      "sl": [
        5,
        5
      ],
      "asl": [
        2000,
        2000
      ]
    }
  },
  "dns": {
    "strategy": "remote|local",
    "prefer": "v4|v6|both",
    "type": "doh|dot|sdns",
    "address": "https://dns.rotunneling.net/dns-query/public",
    "ttl": "300",
    "timeout": "10",
    "fragment": false,
    "hosts": {
      "domain": "dns.rotunneling.net",
      "ip": "172.66.42.222"
    }
  },
  "worker": {
    "enable": "true",
    "sni": "uoosef-worker.uoosef.workers.dev",
    "host": "172.64.136.11:8443",
    "scanner": false
  },
  "udp": {
    "enable": true,
    "timeout": 120
  },
  "unix": {
    "sockets": "protected|normal"
  }
}
`)

type server struct {
	Bind   string `json:"bind"`
	Legacy bool   `json:"legacy"`
	Http   bool   `json:"http"`
}

type tls struct {
	Padding struct {
		Enabled bool   `json:"enabled"`
		Setting [2]int `json:"settings"`
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

type dns struct {
	Strategy string `json:"strategy"`
	Prefer   string `json:"prefer"`
	Type     string `json:"type"`
	Address  string `json:"address"`
	Ttl      int    `json:"ttl"`
	Timeout  string `json:"timeout"`
	Fragment bool   `json:"fragment"`
	Hosts    struct {
		Domain string `json:"domain"`
		Ip     string `json:"ip"`
	} `json:"hosts"`
}

type worker struct {
	Enable  bool   `json:"enable"`
	Sni     string `json:"sni"`
	Host    string `json:"host"`
	Scanner bool   `json:"scanner"`
}

type udp struct {
	Enable  bool `json:"enable"`
	Timeout int  `json:"timeout"`
}

type unix struct {
	Sockets string `json:"sockets"`
}

type session struct {
	ID string
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
		ID: fmt.Sprintf("%d", rand.Intn(8999)+1000),
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
