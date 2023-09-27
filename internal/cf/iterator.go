package cf

import (
	"github.com/uoosef/bepass/internal/cf/jblack"
	"github.com/uoosef/bepass/internal/logger"
	"math/big"
	"math/rand"
	"net"
	"time"
)

type ipRange struct {
	start net.IP
	stop  net.IP
	size  uint64
	index uint64
}

func newIPRange(cidr string) (ipRange, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ipRange{}, err
	}
	return ipRange{start: ipNet.IP, stop: lastIP(ipNet), size: ipRangeSize(ipNet), index: 0}, nil
}

func lastIP(ipNet *net.IPNet) net.IP {
	lastIP := make(net.IP, len(ipNet.IP))
	copy(lastIP, ipNet.IP)
	for i := range ipNet.Mask {
		lastIP[i] |= ^ipNet.Mask[i]
	}
	return lastIP
}

func ipToBigInt(ip net.IP) *big.Int {
	return new(big.Int).SetBytes(ip)
}

func bigIntToIP(n *big.Int) net.IP {
	return n.Bytes()
}

func addIP(ip net.IP, num uint64) net.IP {
	ipInt := ipToBigInt(ip)
	ipInt.Add(ipInt, big.NewInt(int64(num)))
	return bigIntToIP(ipInt)
}

// Function to calculate the number of IP addresses in a CIDR range
func ipRangeSize(ipNet *net.IPNet) uint64 {
	ones, bits := ipNet.Mask.Size()
	return 1 << uint(bits-ones)
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

type ipGenerator struct {
	ipRanges []ipRange
}

func (g *ipGenerator) NextBatch() ([]net.IP, error) {
	var results []net.IP
	for i, ipRange := range g.ipRanges {
		br := jblack.NewBlackrock(ipRange.size, jblack.DefaultRounds, time.Now().UnixNano())
		results = append(results, addIP(ipRange.start, br.Shuffle(ipRange.index)))
		g.ipRanges[i].index++
		g.ipRanges[i].index %= ipRange.size

	}
	return results, nil
}

func newIPGenerator(cidrs []string) *ipGenerator {
	var ranges []ipRange
	for _, cidr := range cidrs {
		ipRange, err := newIPRange(cidr)
		if err != nil {
			logger.Errorf("Error parsing CIDR %s: %v\n", cidr, err)
			continue
		}
		ranges = append(ranges, ipRange)
	}

	return &ipGenerator{
		ipRanges: ranges,
	}
}
