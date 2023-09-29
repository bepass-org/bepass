package scanner

import (
	"context"
	"github.com/uoosef/bepass/internal/config"
	"github.com/uoosef/bepass/internal/logger"
	"github.com/uoosef/bepass/internal/ping"
	"github.com/uoosef/bepass/internal/worker/tools/ipIterator"
	"net"
	"time"
)

type Scanner struct {
	generator *ipIterator.IpGenerator
	ipQueue   *IPQueue
	ctx       context.Context
	cancel    context.CancelFunc
}

func NewScanner(maxQueueSize int, ctx ...context.Context) *Scanner {
	queue := NewIPQueue(maxQueueSize)
	var contextToUse context.Context
	var cancel context.CancelFunc

	if len(ctx) > 0 {
		contextToUse = ctx[0]
	} else {
		contextToUse, cancel = context.WithCancel(context.Background())
	}

	return &Scanner{
		generator: ipIterator.NewIterator(config.Worker.Connection.Hosts),
		ipQueue:   queue,
		ctx:       contextToUse,
		cancel:    cancel,
	}
}

func (s *Scanner) Run() {
	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-s.ipQueue.available:
				logger.Debugf("New Scanning Round Started")
				batch, err := s.generator.NextBatch()
				if err != nil {
					logger.Errorf("Error while generating IP: %v", err)
					// in case of disastrous error, to prevent resource draining wait for 2 seconds and try again
					time.Sleep(2 * time.Second)
					continue
				}
				for _, ip := range batch {
					logger.Debugf("Pinging IP: %s", ip)
					if rtt, err := s.ping(ip); err != nil {
						if rtt < 400 {
							ipInfo := IPInfo{
								IP:        ip,
								RTT:       rtt,
								CreatedAt: time.Now(),
							}
							if !s.ipQueue.Enqueue(ipInfo) {
								<-s.ipQueue.available
							}
						}
					}
				}
			default:
				s.ipQueue.Expire()
			}
		}
	}()
}

func (s *Scanner) Cancel() {
	s.cancel()
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
