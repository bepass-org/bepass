package resolvers

import (
	"bepass/config"
	"fmt"
	"github.com/miekg/dns"
	"net"
)

// SystemResolver represents the config options for setting up a Resolver.
type SystemResolver struct {
	resolverOptions Options
}

// SystemResolverOpts holds options for setting up a System resolver.
type SystemResolverOpts struct{}

// NewSystemResolver accepts a list of nameservers and configures a DNS resolver.
func NewSystemResolver(resolverOpts Options) (Resolver, error) {
	return &SystemResolver{
		resolverOptions: resolverOpts,
	}, nil
}

// Lookup takes a dns.Question and sends them to DNS Server.
func (r *SystemResolver) Lookup(question dns.Question) (Response, error) {
	var rsp Response
	ips, err := net.LookupIP(question.Name)
	if err != nil {
		return rsp, err
	}

	// Separate IPv4 and IPv6 addresses
	var ipv4Addresses []net.IP
	var ipv6Addresses []net.IP

	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4Addresses = append(ipv4Addresses, ip)
		} else {
			ipv6Addresses = append(ipv6Addresses, ip)
		}
	}

	// Print preferred IP version (e.g., IPv4)
	if len(ipv4Addresses) > 0 && r.resolverOptions.Prefer == "ipv4" {
		rsp.Answers = []Answer{
			{
				Name:       question.Name,
				Type:       "A",
				Class:      "IN",                         // Set to IN for Internet class
				TTL:        string(rune(config.Dns.Ttl)), // Set TTL to 1 hour (in seconds)
				Address:    ipv4Addresses[0].String(),
				Status:     "Success",
				RTT:        "N/A",
				Nameserver: "System Resolver",
			},
		}
	} else if len(ipv6Addresses) > 0 && r.resolverOptions.Prefer == "ipv4" {
		ipv6Answers := make([]Answer, len(ipv6Addresses))
		for i, ip := range ipv6Addresses {
			ipv6Answers[i] = Answer{
				Name:       question.Name,
				Type:       "AAAA",
				Class:      "IN",                         // Set to IN for Internet class
				TTL:        string(rune(config.Dns.Ttl)), // Set TTL to 1 hour (in seconds)
				Address:    ip.String(),
				Status:     "Success",
				RTT:        "N/A",
				Nameserver: "System Resolver",
			}
		}
		rsp.Answers = append(rsp.Answers, ipv6Answers...)
	} else {
		fmt.Println("No IP addresses found.")
	}

	return rsp, nil
}
