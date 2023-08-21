package resolve

import (
	"bepass/logger"
	"net"
)

type Hosts struct {
	Domain string
	IP     string
}

type LocalResolver struct {
	Logger *logger.Std
	Hosts  []Hosts
}

func (lr *LocalResolver) Resolve(domain string) string {
	if h := lr.CheckHosts(domain); h != "" {
		return h
	}
	ips, _ := net.LookupIP(domain)
	for _, ip := range ips {
		return ip.String()
	}
	return ""
}
