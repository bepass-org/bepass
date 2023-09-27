package scanner

type IpRTT struct {
	ip  string
	rtt int
}

type IPQueue struct {
	queue []IpRTT
}

func newIPQueue() *IPQueue {
	return &IPQueue{
		queue: make([]IpRTT, 0),
	}
}

func (q *IPQueue) Enqueue(ir IpRTT) {
	q.queue = append(q.queue, ir)
}

func (q *IPQueue) Top() IpRTT {
	return q.queue[0]
}

func (q *IPQueue) Dequeue() IpRTT {
	temp := q.queue[0]
	q.queue = q.queue[1:]
	return temp
}

func (q *IPQueue) Empty() bool {
	return len(q.queue) == 0
}

func (q *IPQueue) size() int {
	return len(q.queue)
}
