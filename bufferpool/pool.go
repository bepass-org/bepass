// Package bufferpool provides a simple buffer pool for getting and returning
// temporary byte slices for use by io.CopyBuffer.
package bufferpool

import "sync"

// BufPool is an interface for getting and returning temporary
// byte slices for use by io.CopyBuffer.
type BufPool interface {
	Get() []byte
	Put([]byte)
}

type pool struct {
	pool *sync.Pool
}

// NewPool creates a new buffer pool for getting and returning temporary
// byte slices for use by io.CopyBuffer.
func NewPool(size int) BufPool {
	return &pool{
		&sync.Pool{
			New: func() interface{} { return make([]byte, size) },
		},
	}
}

// Get implements the BufPool interface.
func (p *pool) Get() []byte {
	return p.pool.Get().([]byte)
}

// Put implements the BufPool interface.
func (p *pool) Put(b []byte) {
	if cap(b) == 0 || len(b) != cap(b) {
		// Invalid buffer size, discard the buffer
		return
	}
	p.pool.Put(b)
}
