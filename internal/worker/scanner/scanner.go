package scanner

import (
	"context"
	"github.com/uoosef/bepass/internal/config"
	"github.com/uoosef/bepass/internal/logger"
	"github.com/uoosef/bepass/internal/worker/tools/ipIterator"
	"net"
	"time"
)

type Scanner struct {
	generator *ipIterator.IpGenerator
	ipQueue   *IPQueue
	ctx       context.Context
	cancel    context.CancelFunc
	ping      func(net.IP) (int, error)
}

func NewScanner(maxQueueSize int, ping func(net.IP) (int, error), ctx ...context.Context) *Scanner {
	queue := NewIPQueue(maxQueueSize)
	var contextToUse context.Context
	var cancel context.CancelFunc

	if len(ctx) > 0 {
		contextToUse = ctx[0]
	} else {
		contextToUse, cancel = context.WithCancel(context.Background())
	}

	return &Scanner{
		ipQueue:   queue,
		ctx:       contextToUse,
		cancel:    cancel,
		ping:      ping,
		generator: ipIterator.NewIterator(config.Worker.Connection.Hosts),
	}
}

func (s *Scanner) GetAvailableIPs() []net.IP {
	return s.ipQueue.AvailableIPs()
}

func (s *Scanner) Run() {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			select {
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
					if rtt, err := s.ping(ip); err == nil {
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
	}
}

func (s *Scanner) Cancel() {
	s.cancel()
}
