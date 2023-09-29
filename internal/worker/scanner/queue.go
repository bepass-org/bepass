package scanner

import (
	"net"
	"sort"
	"sync"
	"time"
)

type IPInfo struct {
	IP        net.IP
	RTT       int
	CreatedAt time.Time
}

type IPQueue struct {
	queue        []IPInfo
	maxQueueSize int
	mu           sync.Mutex
	available    chan struct{}
	wg           sync.WaitGroup
}

func NewIPQueue(maxQueueSize int) *IPQueue {
	return &IPQueue{
		queue:        make([]IPInfo, 0),
		maxQueueSize: maxQueueSize,
		available:    make(chan struct{}, maxQueueSize),
	}
}

func (q *IPQueue) Enqueue(info IPInfo) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.queue) >= q.maxQueueSize {
		return false // Queue is full
	}

	q.available <- struct{}{}

	q.queue = append(q.queue, info)
	q.wg.Add(1)

	return true
}

func (q *IPQueue) Dequeue() (IPInfo, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.queue) == 0 {
		return IPInfo{}, false
	}

	info := q.queue[0]
	q.queue = q.queue[1:]

	<-q.available
	q.wg.Done()

	return info, true
}

func (q *IPQueue) Expire() {
	q.mu.Lock()
	defer q.mu.Unlock()

	for i := 0; i < len(q.queue); i++ {
		if time.Since(q.queue[i].CreatedAt) > 400*time.Millisecond {
			q.queue = append(q.queue[:i], q.queue[i+1:]...)
			i--
			q.wg.Done() // Release a slot in wait group
		}
	}
}

func (q *IPQueue) AvailableIPs() []net.IP {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Create a separate slice for sorting
	sortedQueue := make([]IPInfo, len(q.queue))
	copy(sortedQueue, q.queue)

	// Sort by RTT ascending
	sort.Slice(sortedQueue, func(i, j int) bool {
		return sortedQueue[i].RTT < sortedQueue[j].RTT
	})

	ips := make([]net.IP, len(sortedQueue))
	for i, info := range sortedQueue {
		ips[i] = info.IP
	}

	return ips
}
