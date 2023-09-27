package cf

import (
	"context"
	"github.com/uoosef/bepass/internal/config"
	"github.com/uoosef/bepass/internal/logger"
	"github.com/uoosef/bepass/internal/ping"
	"net"
	"time"
)

type Scanner struct {
	usableIPs *IPQueue
	generator *ipGenerator
}

func NewScanner() *Scanner {
	return &Scanner{
		usableIPs: newIPQueue(),
		generator: newIPGenerator(config.Worker.Connection.Hosts),
	}
}

func (s *Scanner) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			logger.Debugf("Scanner stopped")
			return
		default:
			logger.Debugf("New Scanning Round Started")
			batch, err := s.generator.NextBatch()
			if err != nil {
				logger.Errorf("Error while generating IP: %v", err)
				time.Sleep(120 * time.Second)
				continue
			}
			for _, ip := range batch {
				logger.Debugf("Pinging IP: %s", ip)
				if rtt, err := s.ping(ip); err != nil {
					if rtt > 5000 {
						continue
					}
					s.usableIPs.Enqueue(IpRTT{
						ip:  ip.String(),
						rtt: rtt,
					})
				}
			}
			time.Sleep(120 * time.Second)
		}
	}
}

func (s *Scanner) ping(ip net.IP) (int, error) {
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
	return sum, nil
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
