package endpoint

import (
	"fmt"
	"math/big"
	"math/rand"
	"net"
)

func ipToBigInt(ip net.IP) *big.Int {
	return new(big.Int).SetBytes(ip)
}

func bigIntToIP(n *big.Int) net.IP {
	return n.Bytes()
}

func addBigIntToIP(ip net.IP, num *big.Int) net.IP {
	ipInt := ipToBigInt(ip)
	ipInt.Add(ipInt, num)
	return bigIntToIP(ipInt)
}

func randBigInt(max *big.Int) *big.Int {
	// Generate random bytes
	bytes := make([]byte, max.BitLen()/8+1)
	rand.Read(bytes)

	// Create big int from bytes
	n := new(big.Int).SetBytes(bytes)

	// inc by 1 to make sure don't get 0
	n.Add(n, big.NewInt(1))

	// Make sure < max
	n.Mod(n, max)

	return n
}

func (g *ipGenerator) NextIP() (string, error) {
	if g.currentCIDR >= len(g.cidrs) {
		return "", fmt.Errorf("no IPs left to generate")
	}

	// Get current CIDR network
	network := g.cidrs[g.currentCIDR]

	// Calculate IP range size
	size := ipRangeSize(network)

	// Generate random big.Int
	random := randBigInt(size)

	// Add to base IP
	randomIp := addBigIntToIP(network.IP, random)

	ip := randomIp.String()
	g.incrementIP()
	if g.currentIP().Equal(g.cidrs[g.currentCIDR].IP) {
		g.currentCIDR = rand.Intn(len(g.cidrs))
	}
	return ip, nil
}

func (g *ipGenerator) currentIP() net.IP {
	return g.cidrs[g.currentCIDR].IP
}

func (g *ipGenerator) incrementIP() {
	ip := g.currentIP()
	for i := len(ip) - 1; i >= 0; i-- {
		if ip[i] < 255 {
			ip[i]++
			break
		} else {
			ip[i] = 0
		}
	}
}

// Function to calculate the number of IP addresses in a CIDR range
func ipRangeSize(ipNet *net.IPNet) *big.Int {
	ones, bits := ipNet.Mask.Size()
	ipRangeSize := new(big.Int)
	ipRangeSize.Exp(big.NewInt(2), big.NewInt(int64(bits-ones)), nil)
	return ipRangeSize
}

type ipGenerator struct {
	cidrs       []*net.IPNet
	currentCIDR int
}

func newIPGenerator(cidrs []string) *ipGenerator {
	parsedCidrs := make([]*net.IPNet, len(cidrs))
	for i, cidr := range cidrs {
		_, parsed, _ := net.ParseCIDR(cidr)
		parsedCidrs[i] = parsed
	}

	return &ipGenerator{
		cidrs:       parsedCidrs,
		currentCIDR: rand.Intn(len(parsedCidrs)),
	}
}
