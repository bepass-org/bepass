package resolve

import (
	"net"
)

type Hosts struct {
	Domain string
	IP     string
}

type LocalResolver struct {
	Hosts []Hosts
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
