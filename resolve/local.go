// Package resolve provides DNS resolution and host file management functionality.
package resolve

import (
	"bepass/config"
	"net"
)

// LocalResolver is a resolver that can check a local hosts file for domain-to-IP mappings.
type LocalResolver struct {
	Hosts []config.Hosts
}

// Resolve attempts to resolve a given domain to an IP address. It first checks
// the local hosts file, and if a mapping is found, it returns the corresponding IP.
// If no mapping is found in the hosts file, it performs a DNS lookup for the domain.
// If a DNS lookup succeeds, it returns the first IP address found; otherwise, it returns an empty string.
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
