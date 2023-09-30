// Package endpoint provides a module for generating endpoints based on available IPs.
// It utilizes a scanner to monitor and evaluate the responsiveness of IPs, and selects endpoints
// with higher probabilities for those with lower round-trip times (RTT).
//
// The Generator module can be configured to use either a scanner that performs actual
// ping operations or a shuffler(random scanner) that generates random IPs in given CIDRs
package endpoint

import (
	"context"
	"errors"
	"fmt"
	"github.com/uoosef/bepass/internal/config"
	"github.com/uoosef/bepass/internal/logger"
	"github.com/uoosef/bepass/internal/ping"
	"github.com/uoosef/bepass/internal/worker/scanner"
	"math/rand"
	"net"
	"time"
)

type Generator struct {
	scanner *scanner.Scanner
	ipGen   *ipGenerator
}

func NewGenerator(maxQueueSize int, ctx context.Context) *Generator {
	var pingFunc func(net.IP) (int, error)

	// Initialize scanner based on config.Worker.Connection.Mode
	if config.Worker.Connection.Type == "scanner" {
		pingFunc = actualPing
	} else {
		// if config.Worker.Connection.Type == "random"
		pingFunc = dummyPing
	}

	return &Generator{
		scanner: scanner.NewScanner(maxQueueSize, pingFunc, ctx),
		ipGen:   newIPGenerator(config.Worker.Connection.Hosts),
	}
}

func (eg *Generator) GetEndPoint() (string, error) {
	availableIPs := eg.scanner.GetAvailableIPs()

	if len(availableIPs) == 0 {

		logger.Errorf("scanner is currently empty, using random IP...")
		// Select a random IP from available list of CIDRs
		if ip, err := eg.ipGen.NextIP(); err == nil {
			return ip, nil
		} else {
			return "", errors.New(fmt.Sprintf("error while generating random IP: %v", err))
		}
	}

	// Assign weights to each IP based on its index
	weights := make([]int, len(availableIPs))
	for i := range availableIPs {
		weights[i] = len(availableIPs) - i
	}

	// Calculate total weight
	totalWeight := 0
	for _, weight := range weights {
		totalWeight += weight
	}

	// Generate a random value within the total weight range
	rand.Seed(time.Now().UnixNano())
	randValue := rand.Intn(totalWeight)

	// Find the corresponding IP based on the random value and weights
	var selectedIP net.IP
	for i, weight := range weights {
		if randValue < weight {
			selectedIP = availableIPs[i]
			break
		}
		randValue -= weight
	}

	return selectedIP.String(), nil
}

func (eg *Generator) Run() {
	eg.scanner.Run()
}

func dummyPing(_ net.IP) (int, error) {
	return 100, nil
}

func actualPing(ip net.IP) (int, error) {
	// sum all available ping methods
	sum := 0
	hp, err := httpPing(ip)
	if err != nil {
		return 0, err
	}
	sum += hp
	tp, err := tlsPing(ip)
	if err != nil {
		return 0, err
	}
	sum += tp
	tp, err = tcpPing(ip)
	if err != nil {
		return 0, err
	}
	sum += tp
	return sum / 3, nil
}

func httpPing(ip net.IP) (int, error) {
	hp := ping.NewHttpPing("GET", "https://"+ip.String()+"/", 5*time.Second)
	hp.IP = ip
	pr := hp.Ping()
	err := pr.Error()
	if err != nil {
		return 0, err
	}
	return pr.Result(), nil
}

func tlsPing(ip net.IP) (int, error) {
	tp := ping.NewTlsPing(ip.String(), 443, 5*time.Second, 5*time.Second)
	tp.IP = ip
	pr := tp.Ping()
	err := pr.Error()
	if err != nil {
		return 0, err
	}
	return pr.Result(), nil
}

func tcpPing(ip net.IP) (int, error) {
	tp := ping.NewTcpPing(ip.String(), 443, 5*time.Second)
	pr := tp.Ping()
	err := pr.Error()
	if err != nil {
		return 0, err
	}
	return pr.Result(), nil
}
